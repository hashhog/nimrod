## JSON-RPC server
## Bitcoin Core compatible RPC interface with HTTP Basic auth
## JSON-RPC 2.0 compliant with proper error codes

import std/[json, strutils, tables, options, base64, parseutils, times, sets, os, algorithm, streams, sysrand]
import chronos
import chronicles
import jsony
import ../primitives/[types, serialize]
import ../consensus/[params, validation, chain, versionbits]
import ../storage/[chainstate, blockstore, snapshot, pruner]
import ../storage/indexes/blockfilterindex
import ../storage/indexes/coinstatsindex
import ../storage/indexes/txospenderindex
import ../storage/indexes/gcs as gcsMod
import ../mempool/[mempool, package, persist, orphan]
import ../crypto/[hashing, secp256k1, address, signmessage]
import ../network/[peer, peermanager, banman, messages, asmap, netgroup]
import ../mining/[fees, blocktemplate]
import ../util/ops as opsMod
import ../util/tip_notifier
import ../wallet/wallet
import ../wallet/descriptor
import ../wallet/manager
import ../wallet/psbt
import ../wallet/feebumper
import ../wallet/payjoin
import ../wallet/bip21 as bip21Mod
import ./zmq
import ./mining

type
  RpcError* = object of CatchableError
    code*: int

  RpcServer* = ref object
    port*: uint16
    chainState*: ChainState
    mempool*: Mempool
    peerManager*: PeerManager
    feeEstimator*: FeeEstimator
    params*: ConsensusParams
    authUser*: string
    authPass*: string
    cookiePassword*: string              ## Password for __cookie__ auth (auto-generated)
    running*: bool
    crypto*: CryptoEngine
    blockFileManager*: BlockFileManager  ## Optional: for pruning support
    pruner*: Pruner                      ## Optional: production prune driver
                                          ## (RocksDB delete loop + rev*.dat
                                          ## unlinker). Wired by startNode
                                          ## when --prune=N is passed.
    wallet*: Wallet                      ## Deprecated: use walletManager
    walletManager*: WalletManager        ## Multi-wallet manager
    currentWalletName*: string           ## Current request's target wallet name
    zmq*: ZmqNotificationInterface       ## Optional: ZMQ notification interface
    blockSubmissionPaused*: bool         ## NetworkDisable: when true, submitblock and inbound
                                         ## block handlers refuse new blocks. Set during
                                         ## `dumptxoutset rollback`'s rewind→dump→replay dance
                                         ## to mirror Bitcoin Core's NetworkDisable RAII guard
                                         ## around TemporaryRollback in
                                         ## rpc/blockchain.cpp::dumptxoutset.
    startedAt*: int64                    ## Unix timestamp when this RpcServer was created;
                                         ## used by the `uptime` RPC.
    filterIndex*: BlockFilterIndex       ## Optional BIP-157 basic block-filter index;
                                         ## populated alongside connectBlock in submitblock.
                                         ## Wired by startNode when --blockfilterindex is set.
    coinStatsIndex*: CoinStatsIndex      ## Optional per-height UTXO-set statistics index;
                                         ## maintained alongside connectBlock in submitblock.
                                         ## Wired by startNode when --coinstatsindex is set.
                                         ## Read by gettxoutsetinfo (historical
                                         ## hash_or_height) and getindexinfo.
    txoSpenderIndex*: TxoSpenderIndex    ## Optional spent-outpoint -> spending-tx index
                                         ## (Core's -txospenderindex); maintained alongside
                                         ## connectBlock in submitblock. Wired by startNode
                                         ## when --txospenderindex is set. Read by
                                         ## gettxspendingprevout (confirmed-spend path) and
                                         ## getindexinfo.
    netGroupManager*: NetGroupManager    ## Optional ASMap manager; nil / empty = /16 fallback.
                                         ## Wired by startNode when --asmap is given.
                                         ## Used by getpeerinfo to populate mapped_as.
    orphanPool*: OrphanPool              ## Optional tx orphanage (src/mempool/orphan.nim);
                                         ## holds txs whose parents we haven't seen yet.
                                         ## Wired by startNode; consumed by getorphantxs.
                                         ## nil on test rigs that don't exercise orphans.
    assumeutxoExtra*: seq[AssumeutxoData] ## Runtime-registerable assumeUTXO whitelist
                                          ## entries (mirrors Core chainparams.cpp
                                          ## regtest m_assumeutxo_data). REGTEST ONLY —
                                          ## `registerRegtestAssumeutxo` refuses other
                                          ## networks so mainnet/testnet4 hardcoded
                                          ## entries are never touched. loadtxoutset
                                          ## checks params.assumeutxoData ++ this.
    tipNotifier*: TipNotifier            ## Wake-on-tip-advance primitive for the
                                          ## wait-family RPCs (waitfornewblock /
                                          ## waitforblock / waitforblockheight).
                                          ## Fired from the chainstate connect /
                                          ## reorg chokepoints (main thread), and
                                          ## awaited here on the RPC thread. nil =
                                          ## no notifier wired (tests / degraded
                                          ## boot); the wait handlers then return
                                          ## the current tip immediately rather
                                          ## than block. See src/util/tip_notifier.nim.
    snapshotActivation*: SnapshotActivation ## Live snapshot/background dual-chainstate
                                            ## once `loadtxoutset` has activated a
                                            ## snapshot. nil = single normal chainstate.
                                            ## Read by getchainstates (validated +
                                            ## snapshot_blockhash).

  RpcRequest = object
    jsonrpc: string
    id: JsonNode
    `method`: string
    params: JsonNode

  RpcResponse = object
    jsonrpc: string
    id: JsonNode
    result: JsonNode
    error: JsonNode

# JSON-RPC 2.0 error codes
const
  RpcParseError* = -32700
  RpcInvalidRequest* = -32600
  RpcMethodNotFound* = -32601
  RpcInvalidParams* = -32602
  RpcInternalError* = -32603

  # Bitcoin Core specific error codes
  RpcInvalidParameter* = -8        # Invalid, missing or duplicate parameter (Core RPC_INVALID_PARAMETER)
  RpcInvalidAddressOrKey* = -5     # Invalid address or key
  RpcTypeError* = -3               # Unexpected type was passed as parameter (Core RPC_TYPE_ERROR)
  RpcWalletError* = -4             # Generic wallet RPC error (Core RPC_WALLET_ERROR)
  RpcDeserializationError* = -22   # Error parsing or validating structure (Core RPC_DESERIALIZATION_ERROR)
  RpcTransactionError* = -25       # Generic transaction error
  RpcTransactionRejected* = -26    # Transaction rejected by mempool
  RpcTransactionAlreadyInChain* = -27  # Transaction already confirmed
  RpcMiscError* = -1               # Generic misc error

  # P2P node-management RPC error codes (Core rpc/protocol.h:60-63).
  # These let operator scripts distinguish a duplicate-add / stale-remove /
  # not-connected / bad-IP no-op from a generic JSON-RPC transport failure,
  # exactly as Bitcoin Core does in rpc/net.cpp (addnode / setban /
  # disconnectnode). Non-consensus — RPC-layer error returns only.
  RpcClientNodeAlreadyAdded* = -23   # addnode "add" of an already-added node
  RpcClientNodeNotAdded* = -24       # addnode "remove" of a never-added node
  RpcClientNodeNotConnected* = -29   # disconnectnode for a peer not connected
  RpcClientInvalidIpOrSubnet* = -30  # setban with an invalid IP/subnet string
  RpcClientP2pDisabled* = -31        # P2P/connman unavailable (Core RPC_CLIENT_P2P_DISABLED;
                                     # EnsureConnman throws this for setnetworkactive)

  # Default maxfeerate: 0.10 BTC/kvB = 10,000,000 sat/kvB = 10,000 sat/vB
  DefaultMaxFeeRate* = 0.10  # BTC/kvB

  # Batch request limit to prevent DoS
  MaxBatchSize* = 1000

proc newRpcError(code: int, msg: string): ref RpcError =
  result = newException(RpcError, msg)
  result.code = code

proc newRpcServer*(
  port: uint16,
  chainState: ChainState,
  mempool: Mempool,
  peerManager: PeerManager,
  feeEstimator: FeeEstimator,
  params: ConsensusParams,
  authUser: string = "",
  authPass: string = "",
  cookiePassword: string = ""
): RpcServer =
  RpcServer(
    port: port,
    chainState: chainState,
    mempool: mempool,
    peerManager: peerManager,
    feeEstimator: feeEstimator,
    params: params,
    authUser: authUser,
    authPass: authPass,
    cookiePassword: cookiePassword,
    running: false,
    crypto: newCryptoEngine(),
    blockSubmissionPaused: false,
    startedAt: getTime().toUnix()
  )

proc isBlockSubmissionPaused*(rpc: RpcServer): bool =
  ## Whether inbound block acceptance is currently gated by an active
  ## `dumptxoutset rollback`. Mirrors Bitcoin Core's NetworkDisable check
  ## in rpc/blockchain.cpp::dumptxoutset.
  rpc != nil and rpc.blockSubmissionPaused

proc registerRegtestAssumeutxo*(rpc: RpcServer, data: AssumeutxoData) =
  ## Register a runtime assumeUTXO whitelist entry. REGTEST ONLY — mirrors
  ## Bitcoin Core's hardcoded `m_assumeutxo_data` for regtest
  ## (kernel/chainparams.cpp), which Core ships empty so tests can supply their
  ## own. Refuses any non-regtest network so the mainnet/testnet4 hardcoded
  ## entries can never be altered at runtime.
  if rpc.params.network != Regtest:
    raise newRpcError(RpcMiscError,
      "registerRegtestAssumeutxo: refusing to register a runtime assumeutxo " &
      "entry on a non-regtest network (" & $rpc.params.network & ")")
  rpc.assumeutxoExtra.add(data)

proc effectiveAssumeutxoData*(rpc: RpcServer): seq[AssumeutxoData] =
  ## The assumeUTXO whitelist the live loadtxoutset gate checks against:
  ## the hardcoded per-network `params.assumeutxoData` plus any runtime
  ## regtest entries registered via `registerRegtestAssumeutxo`.
  result = rpc.params.assumeutxoData
  for d in rpc.assumeutxoExtra:
    result.add(d)

proc toHex(data: openArray[byte]): string =
  result = ""
  for b in data:
    result.add(toHex(b, 2).toLowerAscii)

proc reverseHex(hex: string): string =
  result = ""
  var i = hex.len - 2
  while i >= 0:
    result.add(hex[i .. i + 1])
    i -= 2

proc hexToBytes(hex: string): seq[byte] =
  result = newSeq[byte](hex.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(hex[i*2 .. i*2 + 1]))

proc parseBlockHash(hashHex: string): BlockHash =
  var hashBytes: array[32, byte]
  let reversedHex = reverseHex(hashHex)
  for i in 0 ..< 32:
    hashBytes[i] = byte(parseHexInt(reversedHex[i*2 .. i*2 + 1]))
  BlockHash(hashBytes)

proc parseTxId(txidHex: string): TxId =
  var hashBytes: array[32, byte]
  let reversedHex = reverseHex(txidHex)
  for i in 0 ..< 32:
    hashBytes[i] = byte(parseHexInt(reversedHex[i*2 .. i*2 + 1]))
  TxId(hashBytes)

proc validateHashV*(hashHex: string, name: string) =
  ## Mirror of Bitcoin Core's ParseHashV (rpc/util.cpp:117). A txid/blockhash
  ## arg that is NOT a valid 64-char hex uint256 is rejected at the parse
  ## boundary with RPC_INVALID_PARAMETER (-8), BEFORE any lookup, using Core's
  ## exact two messages (wrong length vs. non-hex). A well-formed-but-absent
  ## 64-hex hash is the caller's concern and must keep its -5 / null behavior.
  if hashHex.len != 64:
    raise newRpcError(RpcInvalidParameter,
      name & " must be of length 64 (not " & $hashHex.len & ", for '" & hashHex & "')")
  for c in hashHex:
    if c notin {'0'..'9', 'a'..'f', 'A'..'F'}:
      raise newRpcError(RpcInvalidParameter,
        name & " must be hexadecimal string (not '" & hashHex & "')")

# Forward declarations: the Core-exact difficulty helpers are defined further
# down (alongside the chainwork formatter), but getblockchaininfo/getdifficulty
# above them need the byte-identical-to-Core serializer too.
proc getDifficultyFromBits(bits: uint32): float64
proc difficultyJson(d: float64): JsonNode
# getblockchaininfo (above) needs the same Core-exact chainwork BE formatter
# that getblockheader uses; both are defined further down.
proc computeChainwork*(cdb: ChainDb, startHash: BlockHash, height: int32): array[32, byte]
proc chainworkHexBE*(w: array[32, byte]): string

proc bitsToTarget(bits: uint32): array[32, byte] =
  compactToTarget(bits)

proc targetToDifficulty(target: array[32, byte]): float64 =
  ## Calculate difficulty from target
  ## difficulty = max_target / target
  ## max_target = 0x00000000FFFF... (mainnet genesis target)

  # Find highest non-zero byte in target
  var targetVal: float64 = 0
  for i in countdown(31, 0):
    if target[i] != 0:
      targetVal = float64(target[i])
      for j in countdown(i - 1, max(0, i - 7)):
        targetVal = targetVal * 256 + float64(target[j])
      # Shift by remaining bytes
      let shift = i - 7
      if shift > 0:
        for _ in 0 ..< shift:
          targetVal = targetVal * 256
      break

  if targetVal == 0:
    return 0.0

  # Max target from genesis block (0x1d00ffff in compact form)
  let maxTarget = 26959535291011309493156476344723991336010898738574164086137773096960.0
  maxTarget / targetVal

# ============================================================================
# Shared deployment-state helper
# Both getblockchaininfo (.softforks) and getdeploymentinfo (.deployments)
# must read from the same source of truth.  This proc is the single point of
# truth; neither handler may embed its own deployment logic.
# Reference: Bitcoin Core rpc/blockchain.cpp SoftForkDescPushBack /
#            DeploymentInfo helpers called by both RPCs.
# ============================================================================

proc buildDeployments*(rpc: RpcServer, targetHash: BlockHash, targetHeight: int32): JsonNode =
  ## Build canonical deployment state for both getblockchaininfo.softforks and
  ## getdeploymentinfo.deployments.  Returns a JSON object keyed by fork id.
  ##
  ## Buried deployments: active = (targetHeight >= activationHeight)
  ## BIP9  deployments: state is derived by running the BIP9 state machine
  ##                    against the live chain (chainState.db), not from any
  ##                    hard-coded table.

  # ----- buried deployments -------------------------------------------------
  proc buriedDeployment(activationHeight: int, currentHeight: int32): JsonNode =
    result = newJObject()
    result["type"] = %"buried"
    result["active"] = %(currentHeight >= int32(activationHeight))
    result["height"] = %activationHeight

  result = newJObject()
  result["bip34"]  = buriedDeployment(rpc.params.bip34Height,  targetHeight)
  result["bip65"]  = buriedDeployment(rpc.params.bip65Height,  targetHeight)
  result["bip66"]  = buriedDeployment(rpc.params.bip66Height,  targetHeight)
  result["csv"]    = buriedDeployment(rpc.params.csvHeight,    targetHeight)
  result["segwit"] = buriedDeployment(rpc.params.segwitHeight, targetHeight)

  # ----- BIP9 deployments ---------------------------------------------------
  # State is computed live from chainState.db + the versionbits state machine.
  let cs = rpc.chainState

  let getBlockIndexFn = proc(h: BlockHash): Option[BlockIndex] =
    cs.db.getBlockIndex(h)

  let getMtpFn = proc(h: BlockHash): int64 =
    getMtpForBlock(h, getBlockIndexFn)

  proc bip9Deployment(dep: BIP9Deployment, depIdx: int): JsonNode =
    var stateCache = initTable[BlockHash, ThresholdState]()

    # State is for the block *following* targetHash (prevHash = targetHash)
    let state     = getStateFor(dep, targetHash, getBlockIndexFn, getMtpFn, stateCache)
    let sinceHeight = getStateSinceHeight(dep, targetHash, getBlockIndexFn, getMtpFn, stateCache)

    let bip9Obj = newJObject()
    if state == tsStarted or state == tsLockedIn:
      bip9Obj["bit"] = %dep.bit
    bip9Obj["start_time"]            = %dep.startTime
    bip9Obj["timeout"]               = %dep.timeout
    bip9Obj["min_activation_height"] = %dep.minActivationHeight
    bip9Obj["status"]                = %stateName(state)
    bip9Obj["since"]                 = %sinceHeight

    let nextState = case state
      of tsDefined:
        let mtp = getMtpFn(targetHash)
        if mtp >= dep.startTime: stateName(tsStarted) else: stateName(tsDefined)
      of tsStarted:  stateName(tsLockedIn)
      of tsLockedIn: stateName(tsActive)
      of tsActive:   stateName(tsActive)
      of tsFailed:   stateName(tsFailed)
    bip9Obj["status_next"] = %nextState

    result = newJObject()
    result["type"]   = %"bip9"
    result["active"] = %(state == tsActive)
    result["bip9"]   = bip9Obj

  let testdummy = testDummyDeployment(rpc.params.network)
  let taproot   = taprootDeployment(rpc.params.network)

  result["testdummy"] = bip9Deployment(testdummy, 0)
  result["taproot"]   = bip9Deployment(taproot,   1)

# Blockchain RPCs
proc handleGetBlockchainInfo*(rpc: RpcServer): JsonNode =
  ## Return an object containing various state info regarding blockchain processing
  ## Reference: Bitcoin Core rpc/blockchain.cpp getblockchaininfo

  # Get current tip block for difficulty/bits/target
  var bits = rpc.params.genesisBits
  var blockTime: uint32 = 0
  var medianTime: int64 = 0

  let tipOpt = rpc.chainState.db.getBlock(rpc.chainState.bestBlockHash)
  if tipOpt.isSome:
    let tip = tipOpt.get()
    bits = tip.header.bits
    blockTime = tip.header.timestamp
    # Core's mediantime = GetMedianTimePast() (median of this block + up to 10
    # predecessors), not the tip's raw nTime. Same helper getblockheader uses.
    medianTime = int64(getMtpForHeight(rpc.chainState.db, rpc.chainState.bestHeight))

  let target = bitsToTarget(bits)

  # Calculate verification progress (simplified)
  let verificationProgress = if rpc.chainState.bestHeight < 100:
    float64(rpc.chainState.bestHeight) / 100.0
  else:
    1.0

  # Determine chain name
  let chainName = case rpc.params.network
    of Mainnet: "main"
    of Testnet3: "test"
    of Testnet4: "testnet4"
    of Regtest: "regtest"
    of Signet: "signet"

  # Get pruning info. Two sources of truth:
  #   * `pruner` (when wired) — authoritative for production prune state
  #     (it tracks the RocksDB-backed delete loop and persists pruneHeight).
  #   * `blockFileManager` — fallback, holds the prune-target metadata for
  #     callers that wire bfm without a full Pruner (e.g. tests).
  var pruned = false
  var pruneHeight: int32 = -1
  var sizeOnDisk: uint64 = 0

  if rpc.pruner != nil and rpc.pruner.isPruning:
    pruned = true
    pruneHeight = rpc.pruner.currentPruneHeight()
    sizeOnDisk = rpc.pruner.estimateCurrentUsage()
  elif rpc.blockFileManager != nil:
    pruned = rpc.blockFileManager.isPruneMode
    sizeOnDisk = rpc.blockFileManager.calculateCurrentUsage()
    if pruned:
      pruneHeight = rpc.blockFileManager.getPruneHeight()

  # bits: big-endian %08x of the compact nBits field (Core strprintf("%08x")),
  # matching getblockheader. The old little-endian cast emitted e.g. "ffff7f20"
  # for regtest where Core emits "207fffff".
  let bitsHexBE = toHex([
    byte((bits shr 24) and 0xff),
    byte((bits shr 16) and 0xff),
    byte((bits shr 8) and 0xff),
    byte(bits and 0xff)
  ])

  # chainwork: Core emits nChainWork.GetHex() (big-endian 64-char hex). Recompute
  # the cumulative work the same Core-exact way getblockheader does, rather than
  # the approximate little-endian rpc.chainState.totalWork.
  let chainworkBE = chainworkHexBE(
    computeChainwork(rpc.chainState.db, rpc.chainState.bestBlockHash,
                     rpc.chainState.bestHeight))

  var response = %*{
    "chain": chainName,
    "blocks": rpc.chainState.bestHeight,
    "headers": rpc.chainState.bestHeight,
    "bestblockhash": reverseHex(toHex(array[32, byte](rpc.chainState.bestBlockHash))),
    "bits": bitsHexBE,
    "target": reverseHex(toHex(target)),
    # Use the Core-exact nBits->double path (getDifficultyFromBits) +
    # difficultyJson serializer so the emitted string is byte-identical to
    # Bitcoin Core (std::setprecision(16)), matching getblockheader/getmininginfo.
    # The old targetToDifficulty(target) path printed the full float64 roundtrip
    # (e.g. 4.6565423739069247e-10 vs Core's 4.656542373906925e-10).
    "difficulty": difficultyJson(getDifficultyFromBits(bits)),
    "time": blockTime,
    "mediantime": medianTime,
    "verificationprogress": verificationProgress,
    "initialblockdownload": rpc.chainState.bestHeight < 100,
    "chainwork": chainworkBE,
    "size_on_disk": sizeOnDisk,
    "pruned": pruned,
    # Core v31.99 emits warnings as an array of strings (empty = no warnings).
    "warnings": newJArray()
  }

  # Add pruneheight only if pruned
  if pruned and pruneHeight >= 0:
    response["pruneheight"] = %pruneHeight

  # Add prune_target_size if pruning is enabled. Prefer the Pruner's value
  # because manual mode (--prune=1) reports the AutoPruneFloor as the
  # underlying byte budget while signalling the manual flavor via mode.
  if rpc.pruner != nil and rpc.pruner.isPruning:
    response["prune_target_size"] = %rpc.pruner.currentTargetBytes()
  elif rpc.blockFileManager != nil and rpc.blockFileManager.isPruneMode:
    response["prune_target_size"] = %rpc.blockFileManager.getPruneTarget()

  # NOTE: Core v31.99 REMOVED the "softforks" object from getblockchaininfo
  # (softfork state now lives in getdeploymentinfo only). Do not emit it here.

  response

proc handleGetChainStates(rpc: RpcServer): JsonNode =
  ## Return information about chainstates.
  ## Reference: Bitcoin Core rpc/blockchain.cpp getchainstates (line 3462) +
  ## RPCHelpForChainstate (3449-3460) / make_chain_data.
  ##
  ## nimrod runs a single fully-validated chainstate UNTIL `loadtxoutset`
  ## activates a snapshot. Without a snapshot, `chainstates` is a 1-element
  ## array with validated=true and snapshot_blockhash OMITTED. After
  ## `loadtxoutset` (handleLoadTxOutSetImpl) spins up the real background
  ## dual-chainstate, the element reports the live snapshot verdict:
  ## validated reflects the snapshot chainstate's assumeutxo state (false while
  ## the background re-validation runs / after a hash MISMATCH, true after a
  ## MATCH) and snapshot_blockhash names the snapshot base. Either way the array
  ## is trivially "most-work (active) chainstate last".

  # headers: number of headers seen so far (Core: chainman.m_best_header->nHeight,
  # or -1 if none). nimrod connects headers and blocks together — it does not keep
  # a header index that runs ahead of the connected tip — so the best-header height
  # equals the active tip height. -1 only if there is genuinely no tip (no genesis).
  let headers: int32 =
    if rpc.chainState.bestHeight < 0: -1'i32
    else: rpc.chainState.bestHeight

  # Active chainstate tip → bits/difficulty/target. Mirror handleGetBlockchainInfo:
  # read the tip block's nBits, falling back to the network genesis bits if the tip
  # block body is not retrievable.
  var bits = rpc.params.genesisBits
  let tipOpt = rpc.chainState.db.getBlock(rpc.chainState.bestBlockHash)
  if tipOpt.isSome:
    bits = tipOpt.get().header.bits

  let target = bitsToTarget(bits)

  # verificationprogress: Core's GuessVerificationProgress(tip) → [0..1] progress
  # towards the network tip. With headers == blocks (single connected chain, no
  # header lead), this is 1.0 once past the early-blocks ramp, matching
  # handleGetBlockchainInfo's progress.
  let verificationProgress: float64 =
    if headers <= 0: 0.0
    elif rpc.chainState.bestHeight >= headers: 1.0
    else: float64(rpc.chainState.bestHeight) / float64(headers)

  var chainstate = %*{
    "blocks": rpc.chainState.bestHeight,
    "bestblockhash": reverseHex(toHex(array[32, byte](rpc.chainState.bestBlockHash))),
    # bits: big-endian %08x of the compact nBits field (Core strprintf("%08x")),
    # matching handleGetBlockchainInfo / getblockheader.
    "bits": toHex([
      byte((bits shr 24) and 0xff),
      byte((bits shr 16) and 0xff),
      byte((bits shr 8) and 0xff),
      byte(bits and 0xff)
    ]),
    # target: Core emits GetTarget(...).GetHex() — full 64-char big-endian uint256.
    "target": reverseHex(toHex(target)),
    # difficulty: Core-exact nBits->double path + difficultyJson serializer so the
    # emitted number is byte-identical to Bitcoin Core (std::setprecision(16)).
    "difficulty": difficultyJson(getDifficultyFromBits(bits)),
    "verificationprogress": verificationProgress,
    # coins_db_cache_bytes: Core's m_coinsdb_cache_size_bytes — the on-disk coins
    # (UTXO) DB cache budget. nimrod serves coins from RocksDB with the shared
    # block cache configured via defaultDbConfig().blockCacheSize == BlockCacheSize
    # (src/storage/db.nim). Genuine configured value, not fabricated.
    "coins_db_cache_bytes": int64(BlockCacheSize),
    # coins_tip_cache_bytes: Core's m_coinstip_cache_size_bytes — the in-memory
    # coins-tip cache budget. nimrod's configured coins-cache byte budget
    # (CoinsTipCacheBytes = 450 MiB). NOTE the live ChainState flushes by entry
    # count (maxCacheSize, default 50000), not bytes, so this is the configured
    # dbcache split rather than a live byte meter — documented in notes.
    "coins_tip_cache_bytes": int64(CoinsTipCacheBytes),
    # validated: Core's (m_assumeutxo == VALIDATED). Set below — true for the
    # always-validated single chainstate, or the live snapshot verdict when a
    # snapshot is active.
    "validated": true
  }
  # snapshot_blockhash is OPTIONAL — Core pushes it only for a from-snapshot
  # chainstate. When `loadtxoutset` has activated a snapshot, report the live
  # dual-chainstate verdict: `validated` reflects the snapshot chainstate's
  # assumeutxo state (false while the background re-validation runs OR after a
  # hash MISMATCH, true after a MATCH), and snapshot_blockhash names the base.
  # Mirrors Core's make_chain_data over the snapshot chainstate
  # (rpc/blockchain.cpp::getchainstates).
  if rpc.snapshotActivation != nil and
     rpc.snapshotActivation.snapshot != nil:
    let snap = rpc.snapshotActivation.snapshot
    chainstate["validated"] = %(snap.assumeutxo == auValidated)
    if snap.snapshotBlockhash.isSome:
      chainstate["snapshot_blockhash"] = %reverseHex(toHex(
        array[32, byte](snap.snapshotBlockhash.get())))

  %*{
    "headers": headers,
    # Array ordered by work, most-work (active) chainstate LAST. With a single
    # chainstate this is trivially correct.
    "chainstates": [chainstate]
  }

proc handleGetBlockCount(rpc: RpcServer): JsonNode =
  %rpc.chainState.bestHeight

proc handleGetBestBlockHash(rpc: RpcServer): JsonNode =
  %reverseHex(toHex(array[32, byte](rpc.chainState.bestBlockHash)))

proc handleGetSyncState(rpc: RpcServer): JsonNode =
  ## hashhog W70: uniform fleet-wide sync-state report.
  ## Spec: meta-repo `spec/getsyncstate.md`.
  let tipHeight = rpc.chainState.bestHeight
  let tipHash = reverseHex(toHex(array[32, byte](rpc.chainState.bestBlockHash)))
  let isIbd = tipHeight < 100
  let numPeers = if rpc.peerManager != nil:
    rpc.peerManager.connectedPeerCount().uint32
  else:
    0'u32
  let progress = if tipHeight < 100:
    float64(tipHeight) / 100.0
  else:
    1.0
  let chainName = case rpc.params.network
    of Mainnet: "main"
    of Testnet3: "test"
    of Testnet4: "testnet4"
    of Regtest: "regtest"
    of Signet: "signet"
  %*{
    "tip_height": tipHeight,
    "tip_hash": tipHash,
    "best_header_height": tipHeight,
    "best_header_hash": tipHash,
    "initial_block_download": isIbd,
    "num_peers": numPeers,
    "verification_progress": progress,
    "blocks_in_flight": newJNull(),
    "blocks_pending_connect": newJNull(),
    "last_block_received_time": newJNull(),
    "chain": chainName,
    "protocol_version": 70016,
  }

proc handleGetBlockHash(rpc: RpcServer, params: JsonNode): JsonNode =
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing height parameter")

  let height = params[0].getInt()
  # Use ChainState.getBlockHashByHeight which also checks the IBD in-memory map,
  # covering heights not yet flushed to RocksDB (up to 2000 blocks).
  let hashOpt = rpc.chainState.getBlockHashByHeight(int32(height))
  if hashOpt.isNone:
    # Core rpc/blockchain.cpp::getblockhash raises RPC_INVALID_PARAMETER (-8)
    # with this exact message when nHeight < 0 || nHeight > active tip height,
    # BEFORE any index lookup — not the generic JSON-RPC -32602.
    raise newRpcError(RpcInvalidParameter, "Block height out of range")

  %reverseHex(toHex(array[32, byte](hashOpt.get())))

## 256-bit integer helpers for chainwork calculation
## Representation: array[32, byte] big-endian (index 0 = MSB).

proc u256FromBitsTarget(bits: uint32): array[32, byte] =
  ## Convert compact nBits to 256-bit target, big-endian (like compactToTarget
  ## but in big-endian byte order for chainwork arithmetic).
  let exponent = int((bits shr 24) and 0xff)
  let mantissa = bits and 0x007fffff
  if (bits and 0x00800000) != 0 or exponent == 0 or mantissa == 0:
    return default(array[32, byte])
  # Place 3-byte mantissa at byte position (32 - exponent) from MSB.
  # The mantissa is: [byte2, byte1, byte0] in big-endian.
  let pos = 32 - exponent  # position of the most-significant mantissa byte
  if pos >= 0 and pos < 32:
    result[pos] = byte((mantissa shr 16) and 0xff)
  if pos + 1 >= 0 and pos + 1 < 32:
    result[pos + 1] = byte((mantissa shr 8) and 0xff)
  if pos + 2 >= 0 and pos + 2 < 32:
    result[pos + 2] = byte(mantissa and 0xff)

proc u256Not(a: array[32, byte]): array[32, byte] =
  for i in 0 ..< 32:
    result[i] = not a[i]

proc u256Add1(a: array[32, byte]): array[32, byte] =
  ## a + 1, big-endian
  result = a
  var carry = 1'u32
  for i in countdown(31, 0):
    let s = uint32(result[i]) + carry
    result[i] = byte(s and 0xff)
    carry = s shr 8
    if carry == 0: break

proc u256Cmp(a, b: array[32, byte]): int =
  for i in 0 ..< 32:
    if a[i] < b[i]: return -1
    if a[i] > b[i]: return 1
  0

proc u256Sub(a, b: array[32, byte]): array[32, byte] =
  var borrow = 0'i32
  for i in countdown(31, 0):
    let diff = int32(a[i]) - int32(b[i]) - borrow
    if diff < 0:
      result[i] = byte(diff + 256)
      borrow = 1
    else:
      result[i] = byte(diff)
      borrow = 0

proc u256MulByte(a: array[32, byte], q: uint32): array[32, byte] =
  var carry = 0'u32
  for i in countdown(31, 0):
    let p = uint32(a[i]) * q + carry
    result[i] = byte(p and 0xff)
    carry = p shr 8

proc u256Div(num, den: array[32, byte]): array[32, byte] =
  ## 256-bit division: num / den (big-endian). Restoring radix-256 long division.
  ## Only used for chainwork calculation (called once per block in getblockheader).
  var rem = default(array[32, byte])
  for i in 0 ..< 32:
    # Shift rem left by 8 bits and bring in next byte of num
    for j in 0 ..< 31:
      rem[j] = rem[j + 1]
    rem[31] = num[i]
    # Binary search for q in [0,255] such that q*den <= rem < (q+1)*den
    var lo = 0'u32
    var hi = 255'u32
    while lo < hi:
      let mid = (lo + hi + 1) div 2
      if u256Cmp(u256MulByte(den, mid), rem) <= 0:
        lo = mid
      else:
        hi = mid - 1
    result[i] = byte(lo)
    rem = u256Sub(rem, u256MulByte(den, lo))

proc u256AddBE(a: var array[32, byte], b: array[32, byte]) =
  ## a += b in-place, big-endian
  var carry = 0'u32
  for i in countdown(31, 0):
    let s = uint32(a[i]) + uint32(b[i]) + carry
    a[i] = byte(s and 0xff)
    carry = s shr 8

proc getBitsProof(bits: uint32): array[32, byte] =
  ## Bitcoin Core's GetBitsProof: (~target / (target+1)) + 1 (big-endian).
  ## Reference: bitcoin-core/src/chain.cpp GetBitsProof().
  let target = u256FromBitsTarget(bits)
  # Check for zero target
  var allZero = true
  for b in target:
    if b != 0: allZero = false; break
  if allZero:
    return default(array[32, byte])
  let notTarget = u256Not(target)
  let targetP1  = u256Add1(target)
  let divided   = u256Div(notTarget, targetP1)
  u256Add1(divided)

proc computeChainwork*(cdb: ChainDb, startHash: BlockHash, height: int32): array[32, byte] =
  ## Walk backwards from startHash to genesis, summing getBitsProof(bits) for
  ## each block.  Returns the correct 256-bit cumulative chainwork (big-endian),
  ## matching Bitcoin Core's nChainWork.
  ##
  ## O(height) RocksDB reads.  getBitsProof results are memoized by bits value
  ## since all blocks in a 2016-block epoch share the same bits (≈400 unique
  ## values for mainnet), keeping the computational cost negligible vs. I/O.
  var proofCache: Table[uint32, array[32, byte]]
  var acc = default(array[32, byte])
  var h   = startHash
  for _ in 0 .. height:
    let idxOpt = cdb.getBlockIndex(h)
    if idxOpt.isNone: break
    let idx = idxOpt.get()
    let bits = idx.header.bits
    let proof =
      if bits in proofCache: proofCache[bits]
      else:
        let p = getBitsProof(bits)
        proofCache[bits] = p
        p
    u256AddBE(acc, proof)
    if idx.height == 0: break  # reached genesis
    h = idx.prevHash
  acc

proc chainworkHexBE*(w: array[32, byte]): string =
  ## Format a big-endian 256-bit chainwork as a 64-char lowercase hex string.
  result = newStringOfCap(64)
  for b in w:
    result.add(toHex(b, 2).toLowerAscii)

proc getDifficultyFromBits(bits: uint32): float64 =
  ## Calculate difficulty from nBits — matches Bitcoin Core's GetDifficulty()
  ## in rpc/blockchain.cpp exactly (std::setprecision(16) << result).
  ## Core: dDiff = 0x0000ffff / mantissa, then adjust by 256× per exponent
  ## shift from the canonical exponent of 29.
  let nShift = int((bits shr 24) and 0xff)
  var dDiff = float64(0x0000ffff) / float64(bits and 0x00ffffff)
  var shift = nShift
  while shift < 29:
    dDiff = dDiff * 256.0
    inc shift
  while shift > 29:
    dDiff = dDiff / 256.0
    dec shift
  dDiff

proc difficultyJson(d: float64): JsonNode =
  ## Serialize a difficulty value as a JSON number matching Core's output.
  ## Core uses std::setprecision(16) (default C++ float format, 16 sig digits,
  ## trailing zeros stripped, no decimal point for integral values).
  ## Uses parseJson(rawFloats=true) to bypass Nim's roundtrip float formatter.
  var s = formatFloat(d, ffDefault, 16)
  # Strip trailing zeros after the decimal point — but ONLY for fixed-point
  # notation. When ffDefault chooses scientific notation (e.g. the regtest
  # powLimit difficulty "4.656542373906925e-10"), the string ends in the
  # exponent, not the mantissa, so naively peeling trailing '0' chars from the
  # end corrupts the exponent ("e-10" -> "e-1", a 1e9 error). Core emits the
  # scientific form verbatim, so leave it untouched.
  if '.' in s and 'e' notin s and 'E' notin s:
    var i = s.len - 1
    while i > 0 and s[i] == '0':
      dec i
    if s[i] == '.':
      dec i
    s = s[0 .. i]
  # Parse as raw JSON number (isUnquoted trick — same as rawNumberNode but
  # inlined here because rawNumberNode is defined later in the file).
  var st = newStringStream(s)
  parseJson(st, "diffnum", false, true)

proc handleGetBlockHeader(rpc: RpcServer, params: JsonNode): JsonNode =
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing blockhash parameter")

  let hashHex = params[0].getStr()
  let verbose = if params.len >= 2: params[1].getBool() else: true

  # Core ParseHashV (blockchain.cpp:639, name "hash"): a malformed blockhash is
  # RPC_INVALID_PARAMETER (-8) before any lookup. A well-formed-but-absent hash
  # keeps the -5 "Block not found" below.
  validateHashV(hashHex, "hash")
  let blockHash = parseBlockHash(hashHex)
  let idxOpt = rpc.chainState.db.getBlockIndex(blockHash)
  if idxOpt.isNone:
    # Core: throw RPC_INVALID_ADDRESS_OR_KEY (-5) "Block not found" for a
    # syntactically-valid hash that is not in the block index.
    # Reference: bitcoin-core/src/rpc/blockchain.cpp:654-656.
    raise newRpcError(RpcInvalidAddressOrKey, "Block not found")

  let idx = idxOpt.get()

  if not verbose:
    # Return raw hex
    let headerBytes = serialize(idx.header)
    return %toHex(headerBytes)

  let target = bitsToTarget(idx.header.bits)

  # bits: big-endian hex of the compact nBits field (e.g. "1d00ffff")
  let bitsHex = toHex([
    byte((idx.header.bits shr 24) and 0xff),
    byte((idx.header.bits shr 16) and 0xff),
    byte((idx.header.bits shr 8) and 0xff),
    byte(idx.header.bits and 0xff)
  ])

  # versionHex: big-endian 8-char hex of version (e.g. "20000002")
  let versionHex = toHex([
    byte((uint32(idx.header.version) shr 24) and 0xff),
    byte((uint32(idx.header.version) shr 16) and 0xff),
    byte((uint32(idx.header.version) shr 8) and 0xff),
    byte(uint32(idx.header.version) and 0xff)
  ])

  # chainwork: recompute the correct 256-bit cumulative work from the stored
  # block bits.  nimrod's stored totalWork used an approximate formula that
  # diverges from Core's (~target/(target+1))+1; we walk backwards from this
  # block and sum getBitsProof() to get the byte-identical value.
  let chainwork    = computeChainwork(rpc.chainState.db, blockHash, idx.height)
  let chainworkHex = chainworkHexBE(chainwork)

  # mediantime: Bitcoin Core GetMedianTimePast() — median of this block and up
  # to 10 predecessors (same window as getMtpForHeight).
  let mediantime = int64(getMtpForHeight(rpc.chainState.db, idx.height))

  # target: big-endian 64-char hex of the full 256-bit difficulty target derived
  # from bits. compactToTarget returns little-endian; reverseHex for big-endian.
  let targetHex = reverseHex(toHex(target))

  # nTx: read from the BlockIndex (populated during block connect, W57).
  # For blocks processed before W57 (nTx=0 in old serialized data), try
  # three fallbacks in order: flatfile BlockIndexEntry, RocksDB cfBlocks
  # full-block, then flatfile loadBlock (FIX-80 — mainnet daily
  # consensus-diff caught getblockheader returning nTx=0 for block 900000
  # because legacy BlockIndex entries were written without nTx AND that
  # block is not in cfBlocks RocksDB; the flatfile blk*.dat has it).
  # Reference: bitcoin-core/src/rpc/blockchain.cpp blockheaderToJSON: nTx
  # comes from pindex->nTx, which is always populated alongside the block.
  var nTx = int(idx.nTx)
  if nTx == 0 and rpc.blockFileManager != nil:
    let bfeOpt = rpc.blockFileManager.getBlockIndex(blockHash)
    if bfeOpt.isSome:
      nTx = int(bfeOpt.get().nTx)
  if nTx == 0:
    let blkOpt = rpc.chainState.db.getBlock(blockHash)
    if blkOpt.isSome:
      nTx = blkOpt.get().txs.len
  if nTx == 0 and rpc.blockFileManager != nil:
    # Last-resort: read the block out of the flatfile blk*.dat. The
    # blockFileManager.loadBlock path is the only source that survives
    # pre-W57 indexing AND non-cfBlocks storage (every mainnet sync the
    # node has done since switching to flatfile-backed block storage).
    let blkOpt = rpc.blockFileManager.loadBlock(blockHash)
    if blkOpt.isSome:
      nTx = blkOpt.get().txs.len

  # Active-chain membership: a block is on the active chain iff the active
  # chain's hash at this height equals this block's hash. Core derives both
  # `confirmations` and `nextblockhash` from this via ComputeNextBlockAndDepth:
  # for an in-chain block confirmations = tip - height + 1 and nextblockhash is
  # the active-chain block at height+1; for a side-chain block confirmations is
  # -1 and there is no nextblockhash.
  # Reference: bitcoin-core/src/rpc/blockchain.cpp ComputeNextBlockAndDepth +
  # blockheaderToJSON:162-180.
  let activeHashAtHeight = rpc.chainState.db.getBlockHashByHeight(idx.height)
  # height > bestHeight cannot be on the active chain (getBlockHashByHeight may
  # return a stale above-tip entry after a bare invalidateblock).
  let inActiveChain = idx.height <= rpc.chainState.bestHeight and
    activeHashAtHeight.isSome and activeHashAtHeight.get() == idx.hash

  # Core blockheaderToJSON key order (rpc/blockchain.cpp:159-176):
  #   hash, confirmations, height, version, versionHex, merkleroot, time,
  #   mediantime, nonce, bits, target, difficulty, chainwork, nTx,
  #   [previousblockhash], [nextblockhash].
  var response = newJObject()
  response["hash"] = %reverseHex(toHex(array[32, byte](idx.hash)))
  response["confirmations"] =
    if inActiveChain: %int(rpc.chainState.bestHeight - idx.height + 1)
    else: %(-1)
  response["height"] = %idx.height
  response["version"] = %idx.header.version
  response["versionHex"] = %versionHex
  response["merkleroot"] = %reverseHex(toHex(idx.header.merkleRoot))
  response["time"] = %int64(idx.header.timestamp)
  response["mediantime"] = %mediantime
  response["nonce"] = %idx.header.nonce
  response["bits"] = %bitsHex
  response["target"] = %targetHex
  response["difficulty"] = difficultyJson(getDifficultyFromBits(idx.header.bits))
  response["chainwork"] = %chainworkHex
  response["nTx"] = %nTx

  # Add previousblockhash if not genesis
  if idx.height > 0:
    response["previousblockhash"] = %reverseHex(toHex(array[32, byte](idx.prevHash)))

  # Add nextblockhash if this block is on the active chain AND not the tip.
  # Core's pnext is null for a side-chain block, so nextblockhash is omitted.
  if inActiveChain and idx.height < rpc.chainState.bestHeight:
    let nextHashOpt = rpc.chainState.db.getBlockHashByHeight(idx.height + 1)
    if nextHashOpt.isSome:
      response["nextblockhash"] = %reverseHex(toHex(array[32, byte](nextHashOpt.get())))

  response

proc resolveGetBlockFromPeer*(rpc: RpcServer, blockHash: BlockHash,
                              peerId: int): tuple[peer: Peer, invs: seq[InvVector]] =
  ## Core-`FetchBlock` analog: the pure decision core of getblockfrompeer,
  ## split out so it can be unit-tested without a live socket. Performs the
  ## same ordered checks as Bitcoin Core and, on success, returns the peer to
  ## message plus the getdata inventory to send to it (one MSG_BLOCK |
  ## MSG_WITNESS_FLAG item). Raises RpcError on any failure path.
  ##
  ## Reference: bitcoin-core/src/rpc/blockchain.cpp getblockfrompeer (header
  ## known / block-already-downloaded) + net_processing.cpp
  ## PeerManagerImpl::FetchBlock (peer exists / send getdata invs).

  # (1) The block header must be known. nimrod stores a BlockIndex row for
  #     every header it has accepted (headers-first sync writes the row via
  #     putBlockIndexHashOnly before the body is downloaded), so a present
  #     index entry mirrors Core's non-null LookupBlockIndex.
  #     Core: blockchain.cpp:546-548 → RPC_MISC_ERROR(-1) "Block header missing".
  if rpc.chainState == nil or rpc.chainState.db.getBlockIndex(blockHash).isNone:
    raise newRpcError(RpcMiscError, "Block header missing")

  # (2) The block body must NOT already be on disk. nimrod only writes the
  #     full block (getBlock) once the body has been downloaded + connected,
  #     so a present block body mirrors Core's BLOCK_HAVE_DATA.
  #     Core: blockchain.cpp:556-559 → RPC_MISC_ERROR(-1) "Block already downloaded".
  if rpc.chainState.db.getBlock(blockHash).isSome:
    raise newRpcError(RpcMiscError, "Block already downloaded")

  # (3) Resolve peer_id. nimrod's getpeerinfo numbers peers 0..N-1 as a loop
  #     counter over getReadyPeers() (see handleGetPeerInfo); resolve peer_id
  #     as that same index into the same ordered slice so the id a client sees
  #     in getpeerinfo is the id getblockfrompeer accepts.
  #     Core: net_processing.cpp:1964-1966 → RPC_MISC_ERROR(-1) "Peer does not exist".
  let readyPeers =
    if rpc.peerManager != nil: rpc.peerManager.getReadyPeers()
    else: @[]
  if peerId < 0 or peerId >= readyPeers.len:
    raise newRpcError(RpcMiscError, "Peer does not exist")
  let peer = readyPeers[peerId]

  # (4) Build the block getdata. Core's FetchBlock always requests the witness
  #     serialization (CInv(MSG_BLOCK | MSG_WITNESS_FLAG, hash)) after rejecting
  #     pre-segwit peers; invWitnessBlock is exactly that flag combination
  #     (0x40000002 = MSG_BLOCK | MSG_WITNESS_FLAG).
  #     Core: net_processing.cpp:1979-1981.
  let invs = @[InvVector(invType: invWitnessBlock,
                         hash: array[32, byte](blockHash))]
  (peer, invs)

proc handleGetBlockFromPeer(rpc: RpcServer, params: JsonNode): JsonNode =
  ## getblockfrompeer "blockhash" peer_id
  ## Attempt to fetch a block from a given peer (by its getpeerinfo id).
  ## Returns an empty object {} on success.
  ## Reference: bitcoin-core/src/rpc/blockchain.cpp getblockfrompeer.
  if params.len < 2:
    raise newRpcError(RpcInvalidParams,
      "getblockfrompeer requires 2 parameters: blockhash, peer_id")

  # Core ParseHashV (rpc/util.cpp): a malformed blockhash (non-hex / wrong-
  # length) -> -8 RPC_INVALID_PARAMETER before any lookup, not the -32603 a
  # bare parseBlockHash would raise.
  validateHashV(params[0].getStr(), "blockhash")
  let blockHash = parseBlockHash(params[0].getStr())
  let peerId = params[1].getInt()

  let (peer, invs) = rpc.resolveGetBlockFromPeer(blockHash, peerId)

  # Send a block getdata to that one peer. As with the other P2P-touching RPC
  # handlers in this file (broadcastTx / broadcastBlock) the write is fired via
  # asyncSpawn+spawnSafe so a torn-down transport can't promote a transport
  # race into a process-killing FutureDefect.
  asyncSpawn spawnSafe(peer.sendGetData(invs))

  # Core returns UniValue::VOBJ — an empty object.
  newJObject()

# Forward declarations for helpers defined later in this file that are needed
# by handleGetBlock (verbosity=2 path) and by buildVinJson.
# Nim requires definitions to precede use sites unless forward declarations are
# provided.
proc btcAmountNode*(sats: int64): JsonNode
proc disassembleScriptSigAsmStr*(script: seq[byte]): string
proc buildVinJson(tx: Transaction, inputIndex: int): JsonNode
proc buildVoutJson(output: TxOut, index: int, mainnet: bool,
                   regtest: bool = false): JsonNode

proc blockStrippedSize(b: Block): int =
  ## Block size WITHOUT witness data: 80-byte header + varint(tx_count) +
  ## sum of legacy-serialized (no-witness) tx sizes.
  ## Matches Bitcoin Core's GetBlockWeight's non-witness component.
  var size = 80  # header is always 80 bytes and has no witness
  let txCount = b.txs.len
  # varint size for tx count
  if txCount < 0xFD:
    inc size
  elif txCount <= 0xFFFF:
    size += 3
  elif txCount <= 0xFFFFFFFF:
    size += 5
  else:
    size += 9
  for tx in b.txs:
    size += serializeLegacy(tx).len
  size

proc handleGetBlock(rpc: RpcServer, params: JsonNode): JsonNode =
  ## getblock <hash> [verbosity]
  ##   verbosity=0 → raw hex
  ##   verbosity=1 → header fields + txid array  (default)
  ##   verbosity=2 → header fields + full tx objects with hex + fee
  ##
  ## Reference: bitcoin-core/src/rpc/blockchain.cpp BlockToJSON /
  ## core_io.cpp TxToUniv.  All header fields (bits, versionHex, chainwork,
  ## mediantime, target, difficulty) use the same W57 helpers as
  ## handleGetBlockHeader to achieve byte-identity with Bitcoin Core 31.99.
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing blockhash parameter")

  let hashHex = params[0].getStr()
  let verbosity = if params.len >= 2: params[1].getInt() else: 1

  # Core ParseHashV (blockchain.cpp:842, name "blockhash"): a malformed
  # blockhash is RPC_INVALID_PARAMETER (-8) before any lookup. A well-formed-
  # but-absent hash keeps the not-found behavior below.
  validateHashV(hashHex, "blockhash")
  let blockHash = parseBlockHash(hashHex)

  # Check if block has been pruned
  if rpc.blockFileManager != nil and rpc.blockFileManager.isBlockPruned(blockHash):
    raise newRpcError(RpcMiscError, "Block not available (pruned data)")

  let blkOpt = rpc.chainState.db.getBlock(blockHash)
  if blkOpt.isNone:
    raise newRpcError(RpcInvalidAddressOrKey, "Block not found")

  let b = blkOpt.get()

  if verbosity == 0:
    # Return raw hex
    return %toHex(serialize(b))

  let headerBytes = serialize(b.header)
  let computedHash = doubleSha256(headerBytes)

  # Get block index for height and chainwork
  let idxOpt = rpc.chainState.db.getBlockIndex(blockHash)
  let height = if idxOpt.isSome: idxOpt.get().height else: 0'i32

  # bits: big-endian 8-char hex of the compact nBits field (e.g. "17021ff0")
  # W57: was little-endian, corrected to big-endian (same as getblockheader).
  let bitsHex = toHex([
    byte((b.header.bits shr 24) and 0xff),
    byte((b.header.bits shr 16) and 0xff),
    byte((b.header.bits shr 8) and 0xff),
    byte(b.header.bits and 0xff)
  ])

  # versionHex: big-endian 8-char hex of version (e.g. "20000000")
  # W57: was little-endian, corrected to big-endian (same as getblockheader).
  let versionHex = toHex([
    byte((uint32(b.header.version) shr 24) and 0xff),
    byte((uint32(b.header.version) shr 16) and 0xff),
    byte((uint32(b.header.version) shr 8) and 0xff),
    byte(uint32(b.header.version) and 0xff)
  ])

  # chainwork: recompute via 256-bit arithmetic, same as W57 getblockheader fix.
  # The stored totalWork used an approximate float64 formula; computeChainwork
  # walks backwards summing getBitsProof() per block for byte-identical output.
  let chainwork    = computeChainwork(rpc.chainState.db, blockHash, height)
  let chainworkHex = chainworkHexBE(chainwork)

  # mediantime: median of last 11 blocks (Bitcoin Core GetMedianTimePast).
  # W57: was block.timestamp, now getMtpForHeight (same fix as getblockheader).
  let mediantime = int64(getMtpForHeight(rpc.chainState.db, height))

  # target: big-endian 64-char hex of the 256-bit difficulty target.
  # compactToTarget returns little-endian; reverseHex for big-endian.
  # W57: was toHex(target) (little-endian), now reverseHex(toHex(target)).
  let target    = bitsToTarget(b.header.bits)
  let targetHex = reverseHex(toHex(target))

  # difficulty: use Core-exact getDifficultyFromBits + difficultyJson.
  # W57: old targetToDifficulty() diverged in precision from Core.
  let diffNode = difficultyJson(getDifficultyFromBits(b.header.bits))

  # Block sizes:
  #   size         = full serialization including witness
  #   strippedsize = serialization WITHOUT witness data
  #   weight       = 3 * strippedsize + size  (BIP141)
  # W59: strippedsize was wrongly equal to size (serialize(b).len includes
  # witness).  Now computed via blockStrippedSize().
  let fullSize     = serialize(b).len
  let strippedSize = blockStrippedSize(b)
  let blockWeight  = 3 * strippedSize + fullSize

  let mainnet = rpc.params.network == Mainnet
  let regtest = rpc.params.network == Regtest

  # ── tx array ────────────────────────────────────────────────────────────────
  # verbosity=1 → txid strings; verbosity=2 → full TxToUniv objects with hex.
  var txArray = newJArray()

  # For verbosity=2 fee computation we need the spent input values.
  # Strategy: pre-compute a complete outpoint→value map (feeMap) covering all
  # inputs across all non-coinbase txs in the block.  Sources in priority order:
  #   1. txindex (batch, grouped by creating block) — most accurate, immune to
  #      IBD undo-data corruption.  Block reads are amortized: group all inputs
  #      that reference the same creating block and read that block once.
  #   2. Flat file BlockUndo — per-tx, per-input; covers inputs not in txindex.
  #   3. RocksDB UndoData outpoint map — last resort flat list.
  # Reference: bitcoin-core/src/core_io.cpp TxToUniv (have_undo path) /
  # src/rpc/blockchain.cpp BlockToJSON SHOW_DETAILS case.
  var blockUndoLoaded: Option[BlockUndo]
  var feeMap: Table[OutPoint, int64]   # pre-computed outpoint → satoshi value
  var haveUndo = false

  if verbosity >= 2:
    # ── Phase 1: txindex batch lookup ────────────────────────────────────────
    # Collect all unique spending txids needed, do txindex lookups, group by
    # creating block hash, then read each creating block once.
    #
    # Data structure: blockHash → seq[(spendTxId, txIndex)]
    # For each resolved txid, populate ALL its output values in feeMap
    # (not just the specific vout we saw first), so that multiple inputs
    # spending different vouts of the same creating tx are all covered.
    type TxRef = tuple[spendTxId: TxId, txIndex: int]
    var blockNeeds: Table[BlockHash, seq[TxRef]]
    var resolvedTxids: HashSet[TxId]

    for txIter, txLoop in b.txs:
      if txIter == 0: continue  # skip coinbase
      for inp in txLoop.inputs:
        if inp.prevOut.txid in resolvedTxids: continue
        let locOpt = rpc.chainState.db.getTxIndex(inp.prevOut.txid)
        if locOpt.isSome:
          let loc = locOpt.get()
          if loc.blockHash notin blockNeeds:
            blockNeeds[loc.blockHash] = @[]
          blockNeeds[loc.blockHash].add((inp.prevOut.txid, int(loc.txIndex)))
          resolvedTxids.incl(inp.prevOut.txid)

    # Read each creating block once, extract ALL output values for needed txs.
    for creatingBlockHash, refs in blockNeeds:
      let creatingBlkOpt = rpc.chainState.db.getBlock(creatingBlockHash)
      if creatingBlkOpt.isNone: continue
      let creatingBlk = creatingBlkOpt.get()
      for r in refs:
        if r.txIndex >= creatingBlk.txs.len: continue
        let creatingTx = creatingBlk.txs[r.txIndex]
        # Populate ALL outputs (not just one vout) so multiple inputs spending
        # different outputs of the same creating tx are all covered.
        for voutIdx, creatingOut in creatingTx.outputs:
          let op = OutPoint(txid: r.spendTxId, vout: uint32(voutIdx))
          feeMap[op] = int64(creatingOut.value)

    # ── Phase 2: flat file BlockUndo ─────────────────────────────────────────
    # Pre-load flat file BlockUndo (fast, per-tx structured).
    if idxOpt.isSome:
      let buOpt = rpc.chainState.getBlockUndoFromFile(idxOpt.get(), b.header.prevBlock)
      if buOpt.isSome:
        blockUndoLoaded = buOpt
        haveUndo = true

    # ── Phase 3: RocksDB undo map ────────────────────────────────────────────
    let undoOpt = rpc.chainState.db.getUndoData(blockHash)
    if undoOpt.isSome:
      if not haveUndo: haveUndo = true
      for (op, entry) in undoOpt.get().spentOutputs:
        # Only add to feeMap if not already resolved by txindex (txindex wins).
        if op notin feeMap:
          feeMap[op] = int64(entry.output.value)

  for txIdx, tx in b.txs:
    if verbosity == 1:
      # verbosity=1: emit txid string (legacy hash, reversed for display).
      let txLegacyBytes = serializeLegacy(tx)
      let txidBytes     = doubleSha256(txLegacyBytes)
      txArray.add(%reverseHex(toHex(txidBytes)))
    else:
      # verbosity=2: emit full TxToUniv shape including hex.
      # txid = hash of legacy serialization (no witness)
      # hash = hash of full serialization (wtxid)
      let legacyBytes = serializeLegacy(tx)
      let fullTxBytes = serialize(tx, includeWitness = true)
      let txidHash    = doubleSha256(legacyBytes)
      let wtxidHash   = doubleSha256(fullTxBytes)
      let txidStr     = reverseHex(toHex(txidHash))
      let hashStr     = reverseHex(toHex(wtxidHash))

      let txFullSize  = fullTxBytes.len
      let txBaseSize  = legacyBytes.len
      let txWeight    = txBaseSize * 3 + txFullSize
      let txVsize     = (txWeight + 3) div 4  # ceil(weight/4)

      # Build vin array using the shared W55 buildVinJson helpers.
      var vinArr = newJArray()
      for i in 0 ..< tx.inputs.len:
        vinArr.add(buildVinJson(tx, i))

      # Build vout array using the shared W55 buildVoutJson helpers.
      var voutArr = newJArray()
      for i, outp in tx.outputs:
        voutArr.add(buildVoutJson(outp, i, mainnet, regtest))

      # Core TxToUniv key order: txid, hash, version, size, vsize, weight,
      # locktime, vin, vout, [fee], hex — fee is pushed BEFORE hex.
      var txObj = newJObject()
      txObj["txid"]     = %txidStr
      txObj["hash"]     = %hashStr
      txObj["version"]  = %tx.version
      txObj["size"]     = %txFullSize
      txObj["vsize"]    = %txVsize
      txObj["weight"]   = %txWeight
      txObj["locktime"] = %tx.lockTime
      txObj["vin"]      = vinArr
      txObj["vout"]     = voutArr

      # fee field: sum input values (from the pre-computed feeMap + flat file undo
      # fallback) minus output values.
      # Only present for non-coinbase txs when undo data is available.
      # Reference: bitcoin-core/src/core_io.cpp TxToUniv have_undo block.
      if txIdx > 0:
        var amtIn: int64 = 0
        var amtOut: int64 = 0
        var allInputsKnown = true

        for inpIdx, inp in tx.inputs:
          var inpVal: int64 = -1

          # 1. Pre-computed feeMap (txindex + RocksDB undo, resolved in Phase 1+3).
          inpVal = feeMap.getOrDefault(inp.prevOut, -1'i64)

          # 2. Flat file BlockUndo: per-input prevOutputs (for inputs not in feeMap).
          if inpVal < 0 and blockUndoLoaded.isSome:
            let bu = blockUndoLoaded.get()
            let txUndoIdx = txIdx - 1
            if txUndoIdx < bu.txUndo.len:
              let txUndo = bu.txUndo[txUndoIdx]
              if inpIdx < txUndo.prevOutputs.len:
                inpVal = int64(txUndo.prevOutputs[inpIdx].output.value)

          if inpVal < 0:
            allInputsKnown = false
            break
          amtIn += inpVal

        for outp in tx.outputs:
          amtOut += int64(outp.value)

        let fee = amtIn - amtOut
        if allInputsKnown and fee >= 0:
          txObj["fee"] = btcAmountNode(fee)

      # hex is pushed last (after the optional fee), per Core TxToUniv.
      txObj["hex"] = %toHex(fullTxBytes)

      txArray.add(txObj)

  # Build coinbase_tx summary object (Core 27+ field).
  # Reference: bitcoin-core/src/rpc/blockchain.cpp coinbaseTxToJSON.
  # Core key order: version, locktime, sequence, coinbase, [witness].
  var coinbaseTxObj = newJObject()
  if b.txs.len > 0:
    let cbtx = b.txs[0]
    coinbaseTxObj["version"] = %cbtx.version
    coinbaseTxObj["locktime"] = %cbtx.lockTime
    if cbtx.inputs.len > 0:
      coinbaseTxObj["sequence"] = %cbtx.inputs[0].sequence
      coinbaseTxObj["coinbase"] = %toHex(cbtx.inputs[0].scriptSig)
    # witness: first item of the first witness stack (the BIP141 commitment nonce).
    if cbtx.witnesses.len > 0 and cbtx.witnesses[0].len > 0:
      coinbaseTxObj["witness"] = %toHex(cbtx.witnesses[0][0])

  # Assemble the response object. Core blockToJSON = blockheaderToJSON keys
  # (rpc/blockchain.cpp:159-180) followed by strippedsize, size, weight,
  # coinbase_tx, tx. previousblockhash/nextblockhash are emitted at the end of
  # the header section (before strippedsize).
  var response = newJObject()
  response["hash"]         = %reverseHex(toHex(computedHash))
  # confirmations: Core ComputeNextBlockAndDepth (rpc/blockchain.cpp:116-123)
  # returns -1 for a block NOT on the active chain (e.g. a reorged-out/stale
  # block whose body still exists). Mirror getblockheader's membership check
  # instead of returning best-height-height+1 unconditionally.
  # A block whose height is above the current tip cannot be on the active chain
  # (getBlockHashByHeight may still return a stale above-tip entry after a bare
  # invalidateblock), so guard on height <= bestHeight before the hash compare.
  let activeHashAtHeight = rpc.chainState.db.getBlockHashByHeight(height)
  let inActiveChain = height <= rpc.chainState.bestHeight and
    activeHashAtHeight.isSome and activeHashAtHeight.get() == blockHash
  response["confirmations"] =
    if inActiveChain: %int(rpc.chainState.bestHeight - height + 1)
    else: %(-1)
  response["height"]       = %height
  response["version"]      = %b.header.version
  response["versionHex"]   = %versionHex
  response["merkleroot"]   = %reverseHex(toHex(b.header.merkleRoot))
  response["time"]         = %int64(b.header.timestamp)
  response["mediantime"]   = %mediantime
  response["nonce"]        = %b.header.nonce
  response["bits"]         = %bitsHex
  response["target"]       = %targetHex
  response["difficulty"]   = diffNode
  response["chainwork"]    = %chainworkHex
  response["nTx"]          = %b.txs.len
  if height > 0:
    response["previousblockhash"] = %reverseHex(toHex(array[32, byte](b.header.prevBlock)))
  if height < rpc.chainState.bestHeight:
    let nextHashOpt = rpc.chainState.db.getBlockHashByHeight(height + 1)
    if nextHashOpt.isSome:
      response["nextblockhash"] = %reverseHex(toHex(array[32, byte](nextHashOpt.get())))
  response["strippedsize"] = %strippedSize
  response["size"]         = %fullSize
  response["weight"]       = %blockWeight
  response["coinbase_tx"]  = coinbaseTxObj
  response["tx"]           = txArray

  response

proc handleGetDifficulty(rpc: RpcServer): JsonNode =
  var bits = rpc.params.genesisBits

  # Get bits from current tip if available
  let blkOpt = rpc.chainState.db.getBlock(rpc.chainState.bestBlockHash)
  if blkOpt.isSome:
    bits = blkOpt.get().header.bits

  # Core-exact nBits->double path + difficultyJson serializer for byte-identical
  # output with Bitcoin Core's getdifficulty (std::setprecision(16)).
  difficultyJson(getDifficultyFromBits(bits))

proc handleGetChainTips(rpc: RpcServer): JsonNode =
  # For now, just return the active tip
  # A full implementation would track multiple chain tips
  %*[{
    "height": rpc.chainState.bestHeight,
    "hash": reverseHex(toHex(array[32, byte](rpc.chainState.bestBlockHash))),
    "branchlen": 0,
    "status": "active"
  }]

proc resolveBlockNtx(rpc: RpcServer, idx: BlockIndex): int =
  ## Resolve the number of transactions in a single block, mirroring the
  ## fallback ladder used by handleGetBlockHeader: BlockIndex.nTx first
  ## (populated at connect, W57), then the flatfile BlockIndexEntry, then the
  ## full block out of RocksDB / blk*.dat. Legacy pre-W57 index rows persisted
  ## nTx=0, so the fallbacks are required for an exact cumulative count.
  var nTx = int(idx.nTx)
  if nTx == 0 and rpc.blockFileManager != nil:
    let bfeOpt = rpc.blockFileManager.getBlockIndex(idx.hash)
    if bfeOpt.isSome:
      nTx = int(bfeOpt.get().nTx)
  if nTx == 0:
    let blkOpt = rpc.chainState.db.getBlock(idx.hash)
    if blkOpt.isSome:
      nTx = blkOpt.get().txs.len
  if nTx == 0 and rpc.blockFileManager != nil:
    let blkOpt = rpc.blockFileManager.loadBlock(idx.hash)
    if blkOpt.isSome:
      nTx = blkOpt.get().txs.len
  nTx

proc chainTxCountUpTo(rpc: RpcServer, height: int32): int64 =
  ## Core's CBlockIndex::m_chain_tx_count analogue: the cumulative number of
  ## transactions on the active chain from genesis (height 0) through `height`,
  ## inclusive. Core maintains this as an O(1) running counter at block connect
  ## (prev.m_chain_tx_count + nTx); nimrod does not persist a cumulative field,
  ## so we reconstruct it by walking the active chain by height and summing the
  ## per-block tx count. getchaintxstats is a low-frequency RPC and only needs
  ## two evaluations (window end + window start) per call.
  ## Reference: bitcoin-core/src/chain.h m_chain_tx_count, set in
  ## CBlockIndex by validation.cpp at block connect.
  if height < 0:
    return 0
  var total: int64 = 0
  for h in 0'i32 .. height:
    let hashOpt = rpc.chainState.db.getBlockHashByHeight(h)
    if hashOpt.isNone:
      continue
    let idxOpt = rpc.chainState.db.getBlockIndex(hashOpt.get())
    if idxOpt.isNone:
      continue
    total += int64(rpc.resolveBlockNtx(idxOpt.get()))
  total

proc populateFilterIndexForHashes(rpc: RpcServer, hashes: seq[BlockHash]) =
  ## Advance the BIP-157 basic block-filter index across blocks that were just
  ## connected by a generate* RPC.  Mirrors Bitcoin Core's BaseIndex: the index
  ## hooks BlockConnected for EVERY block that joins the active chain, regardless
  ## of whether it arrived via P2P sync, submitblock, or local mining.  Without
  ## this the index would only advance on the P2P/submitblock paths and lag the
  ## chain tip after `generatetoaddress`, so getindexinfo would report
  ## synced=false / best_block_height < tip.
  ##
  ## The blocks are already connected (UTXO cache mutated), so we read each
  ## block's undo from rev*.dat (when present) — same approach as the daemon's
  ## startup backfill loop.  For empty / coinbase-only regtest blocks there are
  ## no spent prevouts, so the undo is empty and the filter is output-only-complete.
  if rpc.filterIndex == nil or not rpc.filterIndex.enabled:
    return
  let cs = rpc.chainState
  for hash in hashes:
    let idxOpt = cs.db.getBlockIndex(hash)
    if idxOpt.isNone:
      continue
    let bidx = idxOpt.get()
    if bidx.height <= rpc.filterIndex.bestIndexedHeight():
      continue
    let blkOpt = cs.db.getBlock(hash)
    if blkOpt.isNone:
      continue
    let blk = blkOpt.get()
    var blockUndo = chainstate.BlockUndo()
    let buOpt = cs.getBlockUndoFromFile(bidx, blk.header.prevBlock)
    if buOpt.isSome:
      blockUndo = buOpt.get()
    discard rpc.filterIndex.addBlock(blk, hash, bidx.height, blockUndo)

proc populateTxoSpenderIndexForHashes(rpc: RpcServer, hashes: seq[BlockHash]) =
  ## Advance the txospenderindex across blocks just connected by a generate* RPC.
  ## Same rationale as populateFilterIndexForHashes: Core's BaseIndex hooks
  ## BlockConnected for EVERY block joining the active chain, including locally
  ## mined ones.  Without this the index would lag the tip after
  ## generatetoaddress.  No undo needed (keys derive from the block's own
  ## inputs), so this is a plain block-body read.
  if rpc.txoSpenderIndex == nil or not rpc.txoSpenderIndex.enabled:
    return
  let cs = rpc.chainState
  for hash in hashes:
    let idxOpt = cs.db.getBlockIndex(hash)
    if idxOpt.isNone:
      continue
    let bidx = idxOpt.get()
    if bidx.height <= rpc.txoSpenderIndex.bestIndexedHeight():
      continue
    let blkOpt = cs.db.getBlock(hash)
    if blkOpt.isNone:
      continue
    discard rpc.txoSpenderIndex.addBlock(blkOpt.get(), hash, bidx.height,
                                         chainstate.BlockUndo())

proc handleGetBlockFilter(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Retrieve a BIP-157 content filter (and its chained header) for a block.
  ## Byte-faithful to Bitcoin Core
  ## (bitcoin-core/src/rpc/blockchain.cpp getblockfilter, lines 2956-3031):
  ##   getblockfilter "blockhash" ( "filtertype" )
  ##
  ## Returns { "filter": <hex GCS>, "header": <hex 32-byte> } where:
  ##   filter = HexStr(GetEncodedFilter())  — the raw CompactSize(N)||GCS bytes,
  ##            NOT byte-reversed (it is a byte vector, emitted in order).
  ##   header = uint256::GetHex() of the chained filter header — uint256 GetHex()
  ##            emits the bytes in REVERSE (display/big-endian) order, so we
  ##            reverseHex() the internal SHA256d header.
  ##
  ## Error parity (Core):
  ##   unknown filtertype          -> RPC_INVALID_ADDRESS_OR_KEY (-5) "Unknown filtertype"
  ##   filter index not enabled    -> RPC_MISC_ERROR (-1) "Index is not enabled for filtertype basic"
  ##   block hash not in index     -> RPC_INVALID_ADDRESS_OR_KEY (-5) "Block not found"
  if params.len < 1 or params[0].kind != JString:
    raise newRpcError(RpcInvalidParams, "missing blockhash parameter")

  let hashHex = params[0].getStr()

  # filtertype defaults to "basic" (BlockFilterTypeName(BASIC)).
  let filterTypeName =
    if params.len >= 2 and params[1].kind == JString and params[1].getStr().len > 0:
      params[1].getStr()
    else:
      "basic"

  # BlockFilterTypeByName: only "basic" is a known type.  Unknown -> -5.
  # Reference: bitcoin-core/src/rpc/blockchain.cpp:2981-2983.
  if filterTypeName != "basic":
    raise newRpcError(RpcInvalidAddressOrKey, "Unknown filtertype")

  # GetBlockFilterIndex(filtertype): if the basic block filter index is not
  # enabled, Core throws RPC_MISC_ERROR (-1).
  # Reference: bitcoin-core/src/rpc/blockchain.cpp:2985-2988.
  if rpc.filterIndex == nil or not rpc.filterIndex.enabled:
    raise newRpcError(RpcMiscError,
      "Index is not enabled for filtertype " & filterTypeName)

  # LookupBlockIndex: syntactically-valid hash not in the block index -> -5
  # "Block not found".  Reference: bitcoin-core/src/rpc/blockchain.cpp:2995-2998.
  let blockHash = parseBlockHash(hashHex)
  let idxOpt = rpc.chainState.db.getBlockIndex(blockHash)
  if idxOpt.isNone:
    raise newRpcError(RpcInvalidAddressOrKey, "Block not found")
  let bidx = idxOpt.get()

  # LookupFilter + LookupFilterHeader.  nimrod's filter index is height-keyed
  # but the read path verifies the on-disk block_hash matches, so this is
  # exact for active-chain blocks.
  let filterOpt = rpc.filterIndex.getFilter(bidx.height, blockHash)
  let headerOpt = rpc.filterIndex.getFilterHeader(bidx.height)
  if filterOpt.isNone or headerOpt.isNone:
    # Core: "Filter not found." with -5 when the block was not connected.
    # Reference: bitcoin-core/src/rpc/blockchain.cpp:3006-3022.
    raise newRpcError(RpcInvalidAddressOrKey,
      "Filter not found. Block was not connected to active chain.")

  let encoded = gcsMod.getEncodedFilter(filterOpt.get())
  let header = headerOpt.get()

  result = newJObject()
  # filter: raw encoded GCS bytes, lower-hex, NOT reversed.
  result["filter"] = %toHex(encoded)
  # header: uint256 GetHex() — reversed (big-endian display) of the SHA256d.
  result["header"] = %reverseHex(toHex(header))

proc handleGetIndexInfo(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Returns the status of one or all available indices currently running in the
  ## node.  Byte-faithful to Bitcoin Core
  ## (bitcoin-core/src/rpc/node.cpp getindexinfo + SummaryToJSON):
  ##   getindexinfo ( "index_name" )  — one optional positional arg.
  ##
  ## Shape: a dynamic JSON OBJECT keyed BY INDEX NAME.  For each *running* index
  ## one entry is pushed whose value has EXACTLY two fields in this order:
  ##   { "<index name>": { "synced": <bool>, "best_block_height": <int> } }
  ## Nothing else — no best_hash / best_block_hash / name-inside-the-value.
  ##
  ## Index appears ONLY if it is enabled/running (Core guards each with
  ## `if (g_txindex){...}` etc.).  nimrod runs exactly one optional index: the
  ## BIP-157 "basic block filter index" (wired when --blockfilterindex is set).
  ## It does NOT run a txindex / coinstatsindex / txospenderindex, so those keys
  ## are never emitted — Core only lists indexes the node actually runs.
  ##
  ## index_name filter (SummaryToJSON): if index_name is non-empty AND !=
  ## the summary's name, the entry is dropped.  So
  ##   getindexinfo "basic block filter index" -> only that key
  ##   getindexinfo "no-such-index"            -> {} (empty object, NOT an error)
  ## Empty/omitted arg = all running indexes.

  let indexName =
    if params.len >= 1 and params[0].kind == JString: params[0].getStr()
    else: ""

  result = newJObject()

  let tipHeight = rpc.chainState.bestHeight

  # BIP-157 basic block filter index.
  if rpc.filterIndex != nil and rpc.filterIndex.enabled:
    # GetName() string Core emits for the basic filter index
    # (BlockFilterTypeName(BASIC) + " block filter index").
    const name = "basic block filter index"
    if indexName.len == 0 or indexName == name:
      # synced = the index has caught up to the chain tip; best_block_height =
      # the height the index reached (m_best_block_index->nHeight), 0 if none.
      let idxHeight = rpc.filterIndex.bestIndexedHeight()
      let synced = idxHeight >= tipHeight
      let bestHeight = if idxHeight < 0: 0 else: int(idxHeight)
      var entry = newJObject()
      entry["synced"] = %synced
      entry["best_block_height"] = %bestHeight
      result[name] = entry

  # Per-height UTXO-set statistics index (coinstatsindex).  Core's GetName()
  # for this index is "coinstatsindex" (index/coinstatsindex.cpp).
  if rpc.coinStatsIndex != nil and rpc.coinStatsIndex.enabled:
    const name = "coinstatsindex"
    if indexName.len == 0 or indexName == name:
      let idxHeight = rpc.coinStatsIndex.bestIndexedHeight()
      let synced = idxHeight >= tipHeight
      let bestHeight = if idxHeight < 0: 0 else: int(idxHeight)
      var entry = newJObject()
      entry["synced"] = %synced
      entry["best_block_height"] = %bestHeight
      result[name] = entry

  # Spent-outpoint -> spending-tx index (txospenderindex).  Core's GetName() for
  # this index is "txospenderindex" (index/txospenderindex.cpp).
  if rpc.txoSpenderIndex != nil and rpc.txoSpenderIndex.enabled:
    const name = "txospenderindex"
    if indexName.len == 0 or indexName == name:
      let idxHeight = rpc.txoSpenderIndex.bestIndexedHeight()
      let synced = idxHeight >= tipHeight
      let bestHeight = if idxHeight < 0: 0 else: int(idxHeight)
      var entry = newJObject()
      entry["synced"] = %synced
      entry["best_block_height"] = %bestHeight
      result[name] = entry

proc handleGetChainTxStats(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Compute statistics about the total number and rate of transactions in the
  ## chain. Read-only. Byte-faithful to Bitcoin Core
  ## (bitcoin-core/src/rpc/blockchain.cpp getchaintxstats):
  ##   getchaintxstats ( nblocks "blockhash" )  — both args optional.
  ##
  ## Field rules (exact):
  ##   time                       — the FINAL block's RAW header nTime (NOT MTP).
  ##   txcount                    — cumulative #txs genesis..pindex (optional;
  ##                                emitted when known — always known here).
  ##   window_final_block_hash    — pindex block hash.
  ##   window_final_block_height  — pindex height.
  ##   window_block_count         — the resolved nblocks.
  ##   window_interval (optional) — MTP(pindex) - MTP(past_block); only when
  ##                                window_block_count > 0.
  ##   window_tx_count (optional) — txcount(pindex) - txcount(past); only when
  ##                                window > 0 and both endpoints' txcount known.
  ##   txrate (optional)          — window_tx_count / window_interval; only when
  ##                                window_interval > 0 and window_tx_count known.

  # 1. Resolve pindex. params[1] = blockhash (default = active tip).
  var idx: BlockIndex
  let hasBlockhash = params.len >= 2 and params[1].kind != JNull
  if not hasBlockhash:
    let tipOpt = rpc.chainState.db.getBlockIndex(rpc.chainState.bestBlockHash)
    if tipOpt.isNone:
      raise newRpcError(RpcInvalidAddressOrKey, "Block not found")
    idx = tipOpt.get()
  else:
    let blockHash = parseBlockHash(params[1].getStr())
    let idxOpt = rpc.chainState.db.getBlockIndex(blockHash)
    if idxOpt.isNone:
      raise newRpcError(RpcInvalidAddressOrKey, "Block not found")
    idx = idxOpt.get()
    # Must be in the active chain (Core: ActiveChain().Contains(pindex)).
    let atHeight = rpc.chainState.db.getBlockHashByHeight(idx.height)
    if atHeight.isNone or atHeight.get() != idx.hash:
      raise newRpcError(RpcInvalidParameter, "Block is not in main chain")

  # 2. Resolve nblocks. params[0] = nblocks.
  #    Default = 30*24*60*60 / nPowTargetSpacing  ("one month"; 4320 @600s),
  #    then clamped to [0, height-1]. Explicit value must be in [0, height-1].
  let height = idx.height
  var blockcount = (30 * 24 * 60 * 60) div rpc.params.powTargetSpacing
  let hasNblocks = params.len >= 1 and params[0].kind != JNull
  if not hasNblocks:
    blockcount = max(0, min(blockcount, int(height) - 1))
  else:
    blockcount = params[0].getInt()
    if blockcount < 0 or (blockcount > 0 and blockcount >= int(height)):
      raise newRpcError(RpcInvalidParameter,
        "Invalid block count: should be between 0 and the block's height - 1")

  # 3. past_block = ancestor at (height - blockcount), on the active chain.
  let pastHeight = height - int32(blockcount)
  let pastHashOpt = rpc.chainState.db.getBlockHashByHeight(pastHeight)
  if pastHashOpt.isNone:
    raise newRpcError(RpcMiscError, "Could not locate window-start ancestor")
  let pastIdxOpt = rpc.chainState.db.getBlockIndex(pastHashOpt.get())
  if pastIdxOpt.isNone:
    raise newRpcError(RpcMiscError, "Could not locate window-start ancestor")
  let pastIdx = pastIdxOpt.get()

  # window_interval uses MEDIAN-TIME-PAST (11-block window), not raw nTime.
  let nTimeDiff = int64(getMtpForHeight(rpc.chainState.db, height)) -
                  int64(getMtpForHeight(rpc.chainState.db, pastIdx.height))

  # txcount = cumulative #txs genesis..pindex (m_chain_tx_count analogue).
  let txCount = rpc.chainTxCountUpTo(height)
  let haveTxCount = txCount != 0  # genesis alone has >=1 tx -> always true here

  var ret = newJObject()
  # time = the FINAL block's RAW header nTime (NOT mediantime).
  ret["time"] = %int64(idx.header.timestamp)
  if haveTxCount:
    ret["txcount"] = %txCount
  ret["window_final_block_hash"] = %reverseHex(toHex(array[32, byte](idx.hash)))
  ret["window_final_block_height"] = %height
  ret["window_block_count"] = %blockcount
  if blockcount > 0:
    ret["window_interval"] = %nTimeDiff
    let pastTxCount = rpc.chainTxCountUpTo(pastIdx.height)
    let havePastTxCount = pastTxCount != 0
    if haveTxCount and havePastTxCount:
      let windowTxCount = txCount - pastTxCount
      ret["window_tx_count"] = %windowTxCount
      if nTimeDiff > 0:
        ret["txrate"] = %(float64(windowTxCount) / float64(nTimeDiff))
  ret

# ────────────────────────────────────────────────────────────────────────────
# getblockstats
# ────────────────────────────────────────────────────────────────────────────
# Faithful port of bitcoin-core/src/rpc/blockchain.cpp::getblockstats
# (RPCHelpMan + lambda, lines 1956-2214) plus its helpers
# CalculatePercentilesByWeight (1916) and CalculateTruncatedMedian (1901).
#
# Sibling references that were live-verified byte-identical to Core:
#   blockbrew internal/rpc/getblockstats_methods.go
#   hotbuns   src/rpc/server.ts getBlockStats
#   ouroboros src/ouroboros/rpc.py rpc_getblockstats
#
# All amounts are satoshis; feerates are satoshis per virtual byte
# (vsize = weight / 4 → feerate = fee * 4 / weight, integer-truncated).

const
  ## Number of feerate percentiles getblockstats computes (10th, 25th, 50th,
  ## 75th, 90th). Core NUM_GETBLOCKSTATS_PERCENTILES (rpc/blockchain.cpp).
  GetBlockStatsPercentiles = 5

  ## Core PER_UTXO_OVERHEAD: sizeof(COutPoint) + sizeof(uint32_t) + sizeof(bool)
  ##   = (uint256(32) + uint32(4)) + uint32(4) + bool(1) = 41
  ## (bitcoin-core/src/rpc/blockchain.cpp:1953-1954). Added to each output's
  ## serialized size to estimate its on-disk UTXO-set footprint.
  PerUtxoOverhead = 41'i64

  ## Core WITNESS_SCALE_FACTOR (= 4); feerate is fee*4/weight (sat/vB).
  GbsWitnessScaleFactor = 4'i64

  ## Core MAX_BLOCK_SERIALIZED_SIZE, used only as the mintxsize sentinel
  ## (rendered as 0 when no non-coinbase tx is present).
  GbsMaxBlockSerializedSize = 4_000_000'i64

proc txOutSerializeSize(outp: TxOut): int64 =
  ## GetSerializeSize(CTxOut): 8-byte value + CompactSize(scriptlen) + script.
  ## Computed by serializing into a counting buffer, the same idiom
  ## handleGetBlock uses for stripped/full size.
  var w = BinaryWriter()
  w.writeTxOut(outp)
  int64(w.data.len)

proc calculateTruncatedMedian(scores: var seq[int64]): int64 =
  ## Faithful port of Core CalculateTruncatedMedian (blockchain.cpp:1901):
  ##   empty → 0; even count → integer mean of the two central elements
  ##   (truncated toward zero); odd count → the central element. Sorts in place.
  let n = scores.len
  if n == 0:
    return 0
  scores.sort()
  if n mod 2 == 0:
    (scores[n div 2 - 1] + scores[n div 2]) div 2
  else:
    scores[n div 2]

proc calculatePercentilesByWeight(scores: var seq[tuple[rate, weight: int64]],
                                  totalWeight: int64): seq[int64] =
  ## Faithful port of Core CalculatePercentilesByWeight (blockchain.cpp:1916):
  ## the [10th,25th,50th,75th,90th] feerate percentiles selected by cumulative
  ## WEIGHT (not by count). scores are sorted by feerate ascending; a percentile
  ## boundary at total_weight*p is crossed by accumulating each element's weight;
  ## any remaining percentiles are filled with the largest feerate. An empty
  ## score set yields all zeros.
  result = newSeq[int64](GetBlockStatsPercentiles)
  if scores.len == 0:
    return result

  # Sort by feerate ascending; weight as a deterministic tie-break (matches the
  # blockbrew port; Core's std::sort on std::pair orders by .first then .second).
  scores.sort(proc (a, b: tuple[rate, weight: int64]): int =
    if a.rate != b.rate:
      (if a.rate < b.rate: -1 else: 1)
    elif a.weight != b.weight:
      (if a.weight < b.weight: -1 else: 1)
    else:
      0)

  let weights = [
    float64(totalWeight) / 10.0,
    float64(totalWeight) / 4.0,
    float64(totalWeight) / 2.0,
    (float64(totalWeight) * 3.0) / 4.0,
    (float64(totalWeight) * 9.0) / 10.0
  ]

  var nextIdx = 0
  var cumulative: int64 = 0
  for el in scores:
    cumulative += el.weight
    while nextIdx < GetBlockStatsPercentiles and float64(cumulative) >= weights[nextIdx]:
      result[nextIdx] = el.rate
      inc nextIdx
  for i in nextIdx ..< GetBlockStatsPercentiles:
    result[i] = scores[^1].rate

proc computeBlockStats*(b: Block, height: int32, mediantime: int64,
                        subsidy: int64,
                        txInputPrevouts: seq[seq[TxOut]]): JsonNode =
  ## Pure core of getblockstats: compute every statistic for `b`. Always emits
  ## the full do_all object; the handler applies any stats-subset filter.
  ##
  ## `txInputPrevouts[k]` holds the spent prevout TxOuts for the k-th NON-coinbase
  ## transaction, in transaction order (the coinbase is skipped). Both the value
  ## (for fees) and the serialized size (for the utxo_size_inc deltas, which Core
  ## subtracts GetSerializeSize(prevoutput)+PER_UTXO_OVERHEAD for) come from these.
  ## The handler resolves them from undo/txindex/UTXO and refuses the call when a
  ## non-coinbase tx's inputs are unavailable (so we never report a wrong fee).
  ##
  ## Direct port of the per-tx loop in blockchain.cpp:2074-2198.
  var
    maxFee:            int64 = 0
    maxFeeRate:        int64 = 0
    minFee:            int64 = int64(MaxMoney)
    minFeeRate:        int64 = int64(MaxMoney)
    totalOut:          int64 = 0
    totalFee:          int64 = 0
    inputs:            int64 = 0
    maxTxSize:         int64 = 0
    minTxSize:         int64 = GbsMaxBlockSerializedSize
    outputs:           int64 = 0
    swTotalSize:       int64 = 0
    swTotalWeight:     int64 = 0
    swTxs:             int64 = 0
    totalSize:         int64 = 0
    totalWeight:       int64 = 0
    utxos:             int64 = 0   # spendable outputs created (actual numerator)
    utxoSizeInc:       int64 = 0
    utxoSizeIncActual: int64 = 0

    feeArray:     seq[int64]
    feerateArray: seq[tuple[rate, weight: int64]]
    txsizeArray:  seq[int64]

  let isGenesis = height == 0
  var undoIdx = 0  # advances per non-coinbase tx, parallels txInputValues

  for tx in b.txs:
    let coinbase = isCoinbase(tx)
    outputs += int64(tx.outputs.len)

    var txTotalOut: int64 = 0
    for outp in tx.outputs:
      txTotalOut += int64(outp.value)

      let outSize = txOutSerializeSize(outp) + PerUtxoOverhead
      utxoSizeInc += outSize

      # The Genesis block (and BIP30-repeat coinbases, N/A on these networks)
      # do not change the UTXO-set counts; excluded from the actual counters.
      # Core: blockchain.cpp:2088.
      if isGenesis:
        continue
      # Unspendable outputs never enter the UTXO set.
      if isUnspendable(outp.scriptPubKey):
        continue
      inc utxos
      utxoSizeIncActual += outSize

    if coinbase:
      continue

    inputs += int64(tx.inputs.len)  # coinbase's fake input not counted
    totalOut += txTotalOut          # coinbase reward not counted

    # Sizes / weight (always computed; matches Core's do_all path).
    let txSize = int64(serialize(tx, includeWitness = true).len)
    txsizeArray.add(txSize)
    if txSize > maxTxSize: maxTxSize = txSize
    if txSize < minTxSize: minTxSize = txSize
    totalSize += txSize

    let weight = int64(calculateTransactionWeight(tx))
    totalWeight += weight

    if isSegwit(tx):
      inc swTxs
      swTotalSize += txSize
      swTotalWeight += weight

    # Fee + utxo-delta math from the resolved spent prevouts. One entry per
    # non-coinbase tx. Core subtracts each spent prevout's
    # GetSerializeSize(prevoutput) + PER_UTXO_OVERHEAD from both utxo_size_inc
    # counters (blockchain.cpp:2135-2137).
    let prevOuts = txInputPrevouts[undoIdx]
    inc undoIdx

    var txTotalIn: int64 = 0
    for po in prevOuts:
      txTotalIn += int64(po.value)
      let prevoutSize = txOutSerializeSize(po) + PerUtxoOverhead
      utxoSizeInc -= prevoutSize
      utxoSizeIncActual -= prevoutSize

    let txFee = txTotalIn - txTotalOut
    feeArray.add(txFee)
    if txFee > maxFee: maxFee = txFee
    if txFee < minFee: minFee = txFee
    totalFee += txFee

    var feerate: int64 = 0
    if weight != 0:
      feerate = (txFee * GbsWitnessScaleFactor) div weight
    feerateArray.add((rate: feerate, weight: weight))
    if feerate > maxFeeRate: maxFeeRate = feerate
    if feerate < minFeeRate: minFeeRate = feerate

  var feeratePercentiles = calculatePercentilesByWeight(feerateArray, totalWeight)

  let nTx = int64(b.txs.len)
  var nNonCoinbase = nTx - 1
  if nNonCoinbase < 0: nNonCoinbase = 0

  var avgFee: int64 = 0
  var avgTxSize: int64 = 0
  if nNonCoinbase > 0:
    avgFee = totalFee div nNonCoinbase
    avgTxSize = totalSize div nNonCoinbase
  var avgFeeRate: int64 = 0
  if totalWeight != 0:
    avgFeeRate = (totalFee * GbsWitnessScaleFactor) div totalWeight

  if minFee == int64(MaxMoney): minFee = 0
  if minFeeRate == int64(MaxMoney): minFeeRate = 0
  if minTxSize == GbsMaxBlockSerializedSize: minTxSize = 0

  let medianFee = calculateTruncatedMedian(feeArray)
  let medianTxSize = calculateTruncatedMedian(txsizeArray)

  let blockHash = doubleSha256(serialize(b.header))

  var feeratesJson = newJArray()
  for fp in feeratePercentiles:
    feeratesJson.add(%fp)

  result = newJObject()
  result["avgfee"]               = %avgFee
  result["avgfeerate"]           = %avgFeeRate
  result["avgtxsize"]            = %avgTxSize
  result["blockhash"]            = %reverseHex(toHex(blockHash))
  result["feerate_percentiles"]  = feeratesJson
  result["height"]               = %height
  result["ins"]                  = %inputs
  result["maxfee"]               = %maxFee
  result["maxfeerate"]           = %maxFeeRate
  result["maxtxsize"]            = %maxTxSize
  result["medianfee"]            = %medianFee
  result["mediantime"]           = %mediantime
  result["mediantxsize"]         = %medianTxSize
  result["minfee"]               = %minFee
  result["minfeerate"]           = %minFeeRate
  result["mintxsize"]            = %minTxSize
  result["outs"]                 = %outputs
  result["subsidy"]              = %subsidy
  result["swtotal_size"]         = %swTotalSize
  result["swtotal_weight"]       = %swTotalWeight
  result["swtxs"]                = %swTxs
  result["time"]                 = %int64(b.header.timestamp)
  result["total_out"]            = %totalOut
  result["total_size"]           = %totalSize
  result["total_weight"]         = %totalWeight
  result["totalfee"]             = %totalFee
  result["txs"]                  = %nTx
  result["utxo_increase"]        = %(outputs - inputs)
  result["utxo_size_inc"]        = %utxoSizeInc
  result["utxo_increase_actual"] = %(utxos - inputs)
  result["utxo_size_inc_actual"] = %utxoSizeIncActual

proc handleGetBlockStats(rpc: RpcServer, params: JsonNode): JsonNode =
  ## getblockstats hash_or_height ( stats )
  ##
  ## First arg = a block HEIGHT (JSON integer or numeric string) into the active
  ## chain, OR a block HASH (hex). Optional second arg = array of stat names for
  ## a subset (omit/empty = all 31 stats). Faithful port of Bitcoin Core
  ## rpc/blockchain.cpp::getblockstats; matches its field set, percentile method
  ## (weight-ranked) and undo-based fee computation byte-for-byte.
  ##
  ## Fees (per non-coinbase tx): fee = sum(input prevout values) - sum(output
  ## values). Input prevout values come from the block's undo data (flat-file
  ## BlockUndo / RocksDB undo map) with a txindex assist, exactly as
  ## handleGetBlock's verbosity=2 fee path does. The coinbase is excluded from
  ## every fee/feerate statistic but still counts toward txs / outs /
  ## utxo_size_inc.
  ##
  ## Error codes (Core parity):
  ##   -8  height negative / above tip / invalid selected statistic
  ##   -5  block hash not found
  if params.len < 1 or params[0].kind == JNull:
    raise newRpcError(RpcInvalidParams, "Missing hash_or_height parameter")

  # ── 1. Resolve the target block (Core ParseHashOrHeight). ───────────────────
  # A JSON integer, or a string of digits (Core's frontend coerces a numeric
  # string to the NUM arg type), is a height into the ACTIVE chain. Anything
  # else is treated as a block hash.
  var blockHash: BlockHash
  var height: int32

  let arg0 = params[0]
  var asHeight: int64 = 0
  var isHeightArg = false
  if arg0.kind == JInt:
    asHeight = arg0.getBiggestInt()
    isHeightArg = true
  elif arg0.kind == JString:
    let s = arg0.getStr()
    # numeric string → height; otherwise → hash (Core ParseHashOrHeight).
    var allDigits = s.len > 0
    var startIdx = 0
    if s.len > 0 and (s[0] == '+' or s[0] == '-'):
      startIdx = 1
      if s.len == 1: allDigits = false
    for i in startIdx ..< s.len:
      if s[i] < '0' or s[i] > '9':
        allDigits = false
        break
    if allDigits:
      try:
        asHeight = parseBiggestInt(s)
        isHeightArg = true
      except ValueError:
        isHeightArg = false

  if isHeightArg:
    let tip = rpc.chainState.bestHeight
    if asHeight < 0:
      raise newRpcError(RpcInvalidParameter,
        "Target block height " & $asHeight & " is negative")
    if asHeight > int64(tip):
      raise newRpcError(RpcInvalidParameter,
        "Target block height " & $asHeight & " after current tip " & $tip)
    let hashOpt = rpc.chainState.getBlockHashByHeight(int32(asHeight))
    if hashOpt.isNone:
      raise newRpcError(RpcInvalidParameter, "Block height out of range")
    blockHash = hashOpt.get()
    height = int32(asHeight)
  else:
    let hs = arg0.getStr()
    # Core ParseHashV: a malformed hex hash is RPC_INVALID_PARAMETER (-8).
    if hs.len != 64:
      raise newRpcError(RpcInvalidParameter,
        "hash_or_height must be of length 64 (not " & $hs.len & ", for '" & hs & "')")
    try:
      blockHash = parseBlockHash(hs)
    except ValueError:
      raise newRpcError(RpcInvalidParameter,
        "hash_or_height must be hexadecimal string (not '" & hs & "')")
    let idxOpt = rpc.chainState.db.getBlockIndex(blockHash)
    if idxOpt.isNone:
      raise newRpcError(RpcInvalidAddressOrKey, "Block not found")
    height = idxOpt.get().height

  # ── 2. Parse the optional stats filter (do_all when absent/empty). ──────────
  var selected: HashSet[string]
  let doAll = not (params.len >= 2 and params[1].kind == JArray and params[1].len > 0)
  if not doAll:
    for v in params[1]:
      if v.kind != JString:
        raise newRpcError(RpcInvalidParams, "stats entries must be strings")
      selected.incl(v.getStr())

  # ── 3. Load the block body. ─────────────────────────────────────────────────
  if rpc.blockFileManager != nil and rpc.blockFileManager.isBlockPruned(blockHash):
    raise newRpcError(RpcMiscError, "Block not available (pruned data)")
  let blkOpt = rpc.chainState.db.getBlock(blockHash)
  if blkOpt.isNone:
    raise newRpcError(RpcInvalidAddressOrKey, "Block not found")
  let b = blkOpt.get()

  # ── 4. Resolve every non-coinbase tx's spent-prevout values. ────────────────
  # Reuses handleGetBlock's verbosity=2 fee-resolution strategy verbatim:
  #   1. txindex batch lookup (immune to undo-data corruption)
  #   2. flat-file BlockUndo (per-tx, per-input prevOutputs)
  #   3. RocksDB UndoData outpoint map (last resort)
  # Fee stats require EVERY non-coinbase input to be resolvable; if any is
  # missing we error rather than report a wrong fee (Core GetUndoChecked).
  let idxOpt = rpc.chainState.db.getBlockIndex(blockHash)

  # feeMap stores the full spent TxOut (value + scriptPubKey) so the helper can
  # compute both the fee and the exact prevout serialized-size delta Core uses.
  var feeMap: Table[OutPoint, TxOut]
  block populateFeeMap:
    # Phase 1: txindex batch lookup, grouped by creating block.
    type TxRef = tuple[spendTxId: TxId, txIndex: int]
    var blockNeeds: Table[BlockHash, seq[TxRef]]
    var resolvedTxids: HashSet[TxId]
    for txIter, txLoop in b.txs:
      if txIter == 0: continue  # skip coinbase
      for inp in txLoop.inputs:
        if inp.prevOut.txid in resolvedTxids: continue
        let locOpt = rpc.chainState.db.getTxIndex(inp.prevOut.txid)
        if locOpt.isSome:
          let loc = locOpt.get()
          if loc.blockHash notin blockNeeds:
            blockNeeds[loc.blockHash] = @[]
          blockNeeds[loc.blockHash].add((inp.prevOut.txid, int(loc.txIndex)))
          resolvedTxids.incl(inp.prevOut.txid)
    for creatingBlockHash, refs in blockNeeds:
      let creatingBlkOpt = rpc.chainState.db.getBlock(creatingBlockHash)
      if creatingBlkOpt.isNone: continue
      let creatingBlk = creatingBlkOpt.get()
      for r in refs:
        if r.txIndex >= creatingBlk.txs.len: continue
        let creatingTx = creatingBlk.txs[r.txIndex]
        for voutIdx, creatingOut in creatingTx.outputs:
          feeMap[OutPoint(txid: r.spendTxId, vout: uint32(voutIdx))] = creatingOut

    # Phase 3: RocksDB undo map (only fills outpoints txindex missed).
    let undoOpt = rpc.chainState.db.getUndoData(blockHash)
    if undoOpt.isSome:
      for (op, entry) in undoOpt.get().spentOutputs:
        if op notin feeMap:
          feeMap[op] = entry.output

  # Phase 2: flat-file BlockUndo (per-tx, per-input prevOutputs).
  var blockUndoLoaded: Option[BlockUndo]
  if idxOpt.isSome:
    blockUndoLoaded = rpc.chainState.getBlockUndoFromFile(idxOpt.get(),
                                                          b.header.prevBlock)

  var txInputPrevouts: seq[seq[TxOut]]
  var txUndoCounter = 0  # index into BlockUndo.txUndo (per non-coinbase tx)
  for txIdx, tx in b.txs:
    if txIdx == 0:
      continue  # coinbase: no spent prevouts
    var inPrev: seq[TxOut]
    for inpIdx, inp in tx.inputs:
      var resolved = false
      var po: TxOut
      if inp.prevOut in feeMap:
        po = feeMap[inp.prevOut]
        resolved = true
      elif blockUndoLoaded.isSome:
        let bu = blockUndoLoaded.get()
        if txUndoCounter < bu.txUndo.len:
          let txUndo = bu.txUndo[txUndoCounter]
          if inpIdx < txUndo.prevOutputs.len:
            po = txUndo.prevOutputs[inpIdx].output
            resolved = true
      if not resolved:
        # Cannot compute a correct fee for this block — refuse rather than
        # report wrong fee stats. Mirrors Core GetUndoChecked throwing.
        raise newRpcError(RpcMiscError,
          "Undo data unavailable for block (cannot compute fees)")
      inPrev.add(po)
    inc txUndoCounter
    txInputPrevouts.add(inPrev)

  # ── 5. Compute every statistic, then apply any subset filter. ───────────────
  let mediantime = int64(getMtpForHeight(rpc.chainState.db, height))
  let subsidy = int64(getBlockSubsidy(height, rpc.params))
  let full = computeBlockStats(b, height, mediantime, subsidy, txInputPrevouts)

  if doAll:
    return full

  var ret = newJObject()
  for name in selected:
    if not full.hasKey(name):
      raise newRpcError(RpcInvalidParameter,
        "Invalid selected statistic '" & name & "'")
    ret[name] = full[name]
  ret

proc handleGetDeploymentInfo*(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Return deployment info for soft forks at a given block (or chain tip).
  ## Reference: Bitcoin Core rpc/blockchain.cpp getdeploymentinfo
  ##
  ## Optional argument:
  ##   1. blockhash (string) - query at this block; defaults to chain tip
  ##
  ## Deployment data comes exclusively from buildDeployments — the same
  ## helper used by getblockchaininfo.softforks — so the two RPCs are always
  ## in agreement on deployment state.

  # Resolve the target block hash
  var targetHash: BlockHash
  var targetHeight: int32

  if params.len >= 1 and params[0].kind == JString and params[0].getStr().len > 0:
    let hashHex = params[0].getStr()
    if hashHex.len != 64:
      raise newRpcError(RpcInvalidParams, "invalid block hash")
    targetHash = parseBlockHash(hashHex)
    let idxOpt = rpc.chainState.db.getBlockIndex(targetHash)
    if idxOpt.isNone:
      raise newRpcError(RpcInvalidParams, "block not found")
    targetHeight = idxOpt.get().height
  else:
    targetHash = rpc.chainState.bestBlockHash
    targetHeight = rpc.chainState.bestHeight

  let hashDisplay = reverseHex(toHex(array[32, byte](targetHash)))

  result = newJObject()
  result["hash"]        = %hashDisplay
  result["height"]      = %targetHeight
  result["deployments"] = rpc.buildDeployments(targetHash, targetHeight)

# Forward declaration: the wallet history unscan hook is defined alongside the
# block-connect scan hooks (further down, near the mining RPCs) but is needed
# here by handleInvalidateBlock for symmetric reorg/disconnect bookkeeping.
proc unscanBlockFromWallets(rpc: RpcServer, blk: Block, height: int32) {.gcsafe.}
# Forward declaration: the wallet block-connect scan+persist hook is defined
# near the mining RPCs but is needed earlier by handleSubmitBlock so a block
# accepted via submitblock (not just generatetoaddress) feeds + persists the
# wallet. DATA-LOSS FIX wa0fq5wtk.
proc scanBlockIntoWallets(rpc: RpcServer, blk: Block, height: int32,
                          persist: bool = true) {.gcsafe.}

# Chain Management RPCs
proc handleInvalidateBlock(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Permanently marks a block and all its descendants as invalid
  ## Reference: Bitcoin Core rpc/blockchain.cpp invalidateblock
  ##
  ## Arguments:
  ## 1. blockhash (string, required) - The hash of the block to mark as invalid
  ##
  ## Returns: null on success, error on failure

  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing blockhash parameter")

  let hashHex = params[0].getStr()
  # Core ParseHashV: a malformed (non-hex / wrong-length) blockhash is rejected
  # at the parse boundary with -8 RPC_INVALID_PARAMETER (BEFORE any lookup), not
  # the prior -5. A well-formed-but-absent hash stays -5 "Block not found" below.
  validateHashV(hashHex, "blockhash")

  let blockHash = parseBlockHash(hashHex)

  # Check if block exists
  let idxOpt = rpc.chainState.db.getBlockIndex(blockHash)
  if idxOpt.isNone:
    raise newRpcError(RpcInvalidAddressOrKey, "Block not found")

  # Wallet history unscan (symmetric with the block-connect scan): if the block
  # being invalidated is on the active chain, drop the transaction-history
  # records it and every active-chain descendant contributed, so
  # listtransactions/gettransaction never report a tx no longer in the active
  # chain. Best-effort, runs BEFORE the disconnect while the height->hash
  # mapping is still intact. Mirrors Bitcoin Core CWallet::blockDisconnected.
  let invalidHeight = idxOpt.get().height
  if invalidHeight >= 0 and invalidHeight <= rpc.chainState.bestHeight:
    let activeAtHeight = rpc.chainState.db.getBlockHashByHeight(invalidHeight)
    if activeAtHeight.isSome and activeAtHeight.get() == blockHash:
      var h = rpc.chainState.bestHeight
      while h >= invalidHeight:
        let bhOpt = rpc.chainState.db.getBlockHashByHeight(h)
        if bhOpt.isSome:
          let blkOpt = rpc.chainState.db.getBlock(bhOpt.get())
          if blkOpt.isSome:
            rpc.unscanBlockFromWallets(blkOpt.get(), h)
        dec h

  # Call the chain management function
  let result = rpc.chainState.invalidateBlock(blockHash)
  if not result.isOk:
    case result.error
    of cmeCannotInvalidateGenesis:
      raise newRpcError(RpcMiscError, "Cannot invalidate genesis block")
    of cmeBlockNotFound:
      raise newRpcError(RpcInvalidAddressOrKey, "Block not found")
    of cmeUndoDataMissing:
      raise newRpcError(RpcMiscError, "Undo data missing, cannot disconnect block")
    of cmeDisconnectFailed:
      raise newRpcError(RpcMiscError, "Failed to disconnect block from chain")
    else:
      raise newRpcError(RpcMiscError, $result.error)

  newJNull()

proc handleReconsiderBlock(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Removes invalidity status of a block and its descendants
  ## Reference: Bitcoin Core rpc/blockchain.cpp reconsiderblock
  ##
  ## Arguments:
  ## 1. blockhash (string, required) - The hash of the block to reconsider
  ##
  ## Returns: null on success, error on failure
  ##
  ## Note: This does not automatically reconnect the block to the active chain.
  ## You may need to restart the node or wait for a new block to trigger
  ## chain selection.

  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing blockhash parameter")

  let hashHex = params[0].getStr()
  # Core ParseHashV: a malformed (non-hex / wrong-length) blockhash is rejected
  # at the parse boundary with -8 RPC_INVALID_PARAMETER (BEFORE any lookup), not
  # the prior -5. A well-formed-but-absent hash stays -5 "Block not found" below.
  validateHashV(hashHex, "blockhash")

  let blockHash = parseBlockHash(hashHex)

  # Check if block exists
  let idxOpt = rpc.chainState.db.getBlockIndex(blockHash)
  if idxOpt.isNone:
    raise newRpcError(RpcInvalidAddressOrKey, "Block not found")

  # Call the chain management function
  let result = rpc.chainState.reconsiderBlock(blockHash)
  if not result.isOk:
    case result.error
    of cmeBlockNotFound:
      raise newRpcError(RpcInvalidAddressOrKey, "Block not found")
    else:
      raise newRpcError(RpcMiscError, $result.error)

  newJNull()

proc handlePreciousBlock(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Treats a block as if it were received before others with the same work
  ## Reference: Bitcoin Core rpc/blockchain.cpp preciousblock
  ##
  ## Arguments:
  ## 1. blockhash (string, required) - The hash of the block to mark as precious
  ##
  ## Returns: null on success, error on failure
  ##
  ## A precious block will be preferred over other blocks with equal chainwork.
  ## This is useful when you want to manually select which chain to follow
  ## without invalidating the competing chain.

  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing blockhash parameter")

  let hashHex = params[0].getStr()
  # Core ParseHashV: a malformed (non-hex / wrong-length) blockhash is rejected
  # at the parse boundary with -8 RPC_INVALID_PARAMETER (BEFORE any lookup), not
  # the prior -5. A well-formed-but-absent hash stays -5 "Block not found" below.
  validateHashV(hashHex, "blockhash")

  let blockHash = parseBlockHash(hashHex)

  # Check if block exists
  let idxOpt = rpc.chainState.db.getBlockIndex(blockHash)
  if idxOpt.isNone:
    raise newRpcError(RpcInvalidAddressOrKey, "Block not found")

  # Call the chain management function
  let result = rpc.chainState.preciousBlock(blockHash)
  if not result.isOk:
    case result.error
    of cmeBlockNotFound:
      raise newRpcError(RpcInvalidAddressOrKey, "Block not found")
    else:
      raise newRpcError(RpcMiscError, $result.error)

  newJNull()

# Mempool RPCs
proc handleGetMempoolInfo*(rpc: RpcServer): JsonNode =
  # Calculate total fees
  var totalFeeSat: int64 = 0
  for _, entry in rpc.mempool.entries:
    totalFeeSat += int64(entry.fee)

  # Display fields read the REAL admission floor (mp.minFeeRate, sat/vB; default
  # 100 sat/kvB = 0.00000100 BTC per Core DEFAULT_MIN_RELAY_TX_FEE, policy.h:70).
  # Coupled to the live mempool field — NOT a hardcoded literal — so the display
  # can never drift from the floor a tx is actually gated against (CheckFeeRate,
  # mempool.nim:1238). mempoolminfee = max(rolling, static floor); minrelaytxfee
  # = the static floor; incrementalrelayfee = mp.incrementalRelayFeeRate.
  # btcAmountNode takes satoshis (per kvB): sat/vB * 1000 -> sat/kvB.
  # Reference: bitcoin-core/src/rpc/mempool.cpp MempoolInfoToJSON (1048-1063).
  let minRelayFeeRateVb = rpc.mempool.minFeeRate                      # sat/vB
  let mempoolMinFeeRateVb = max(minRelayFeeRateVb, rpc.mempool.getMinFee())
  let minRelaySats = int64(minRelayFeeRateVb * 1000.0 + 0.5)         # sat/kvB
  let mempoolMinSats = int64(mempoolMinFeeRateVb * 1000.0 + 0.5)     # sat/kvB
  let incrementalSats = int64(rpc.mempool.incrementalRelayFeeRate + 0.5)  # sat/kvB

  %*{
    "loaded": true,
    "size": rpc.mempool.count,
    "bytes": rpc.mempool.size,
    "usage": rpc.mempool.size,
    "total_fee": float64(totalFeeSat) / 100000000.0,
    "maxmempool": rpc.mempool.maxSize,
    "mempoolminfee": btcAmountNode(mempoolMinSats),
    "minrelaytxfee": btcAmountNode(minRelaySats),
    "incrementalrelayfee": btcAmountNode(incrementalSats),
    "unbroadcastcount": 0,
    # Core master removed the mempoolfullrbf option and hardcodes `true`
    # (mempool.cpp:1058). Match Core's wire output.
    "fullrbf": true,
    # The 5 policy fields Core v31.99 added after fullrbf, in Core order.
    # Defaults match Core's DEFAULT_* constants (and rustoshi's solved values).
    "permitbaremultisig": true,            # DEFAULT_PERMIT_BAREMULTISIG
    "maxdatacarriersize": 100_000,         # MAX_OP_RETURN_RELAY
    "limitclustercount": 64,               # DEFAULT_CLUSTER_LIMIT
    "limitclustersize": 101_000,           # DEFAULT_CLUSTER_SIZE_LIMIT_KVB * 1000
    "optimal": true                        # DoWork(0) on default mempool
  }

proc parseTxidParam(hexStr: string): TxId =
  ## Decode a 64-char display-format hex txid into the internal LE representation.
  if hexStr.len != 64:
    raise newRpcError(RpcInvalidAddressOrKey, "Invalid txid")
  var bytes: array[32, byte]
  let reversed = reverseHex(hexStr)
  for i in 0 ..< 32:
    bytes[i] = byte(parseHexInt(reversed[i*2 .. i*2+1]))
  TxId(bytes)

proc mempoolEntryJson*(rpc: RpcServer, txid: TxId, entry: MempoolEntry): JsonNode =
  ## Canonical per-entry object for getmempoolentry, getrawmempool (verbose),
  ## getmempoolancestors (verbose), getmempooldescendants (verbose).
  ## Reference: bitcoin-core/src/rpc/mempool.cpp entryToJSON (Core 31.99).
  ##
  ## Field order matches Core exactly.  Notable: top-level "fee"/"modifiedfee"/
  ## "descendantfees"/"ancestorfees" are ABSENT (removed in Core 31.99, replaced
  ## by the "fees" sub-object).  "chunkweight" and "fees.chunk" are added.
  ## W70d: aligned to Core 31.99 entryToJSON field set.
  let vsize = (entry.weight + 3) div 4
  let feeF   = float64(int64(entry.fee))   / 100000000.0
  # modified fee = base + PrioritiseTransaction delta (Core GetModifiedFee).
  # Without a prioritisation this equals the base fee, preserving prior output.
  let modF   = float64(rpc.mempool.getModifiedFee(txid)) / 100000000.0
  let ancestF = float64(int64(entry.ancestorFee)) / 100000000.0
  # descendant fee: nimrod mempool tracks per-entry fee only;
  # for the single-entry case (no descendants) it equals the entry fee.
  let descendF = feeF
  # chunkweight: for now emit weight as a proxy (full cluster-aware
  # chunk scheduling is not yet implemented in nimrod's mempool).
  let chunkWeight = entry.weight
  var obj = newJObject()
  obj["vsize"]           = %vsize
  obj["weight"]          = %entry.weight
  obj["time"]            = %entry.timeAdded.toUnix()
  obj["height"]          = %entry.height
  obj["descendantcount"] = %1
  obj["descendantsize"]  = %vsize
  obj["ancestorcount"]   = %entry.ancestorCount
  obj["ancestorsize"]    = %entry.ancestorSize
  obj["wtxid"]           = %reverseHex(toHex(array[32, byte](entry.tx.wtxid())))
  obj["chunkweight"]     = %chunkWeight
  var feesObj = newJObject()
  feesObj["base"]       = %feeF
  feesObj["modified"]   = %modF
  feesObj["ancestor"]   = %ancestF
  feesObj["descendant"] = %descendF
  feesObj["chunk"]      = %feeF
  obj["fees"]             = feesObj
  obj["depends"]          = newJArray()
  obj["spentby"]          = newJArray()
  # FIX-68 (W120 BUG-3): bip125-replaceable must reflect the tx's actual
  # opt-in state.  Walks the tx itself (Gate 1: any input <= 0xfffffffd)
  # AND walks all unconfirmed in-mempool ancestors (Gate 2: inherited
  # signaling).  In full-RBF mode every mempool tx is replaceable.
  # Reference: bitcoin-core/src/rpc/mempool.cpp entryToJSON
  # → IsRBFOptIn(tx, pool) at line 560.
  obj["bip125-replaceable"] = %rpc.mempool.isBip125Replaceable(txid)
  obj["unbroadcast"]      = %false
  obj

proc handleGetRawMempool(rpc: RpcServer, params: JsonNode): JsonNode =
  ## getrawmempool [verbose] [mempool_sequence]
  ## Reference: bitcoin-core/src/rpc/mempool.cpp getrawmempool / entryToJSON.
  let verbose = if params.len >= 1: params[0].getBool() else: false

  if verbose:
    # Verbose: keyed by txid (display format), value = full entryToJSON object.
    # W70d: was a truncated inline object missing modifiedfee, wtxid, fees,
    # depends, spentby, unbroadcast, and had hardcoded ancestorcount=1.
    # Now delegates to mempoolEntryJson for byte-parity with Core.
    var entries = newJObject()
    for txid, entry in rpc.mempool.entries:
      entries[$txid] = mempoolEntryJson(rpc, txid, entry)
    return entries
  else:
    var txids: seq[string]
    for txid in rpc.mempool.entries.keys:
      txids.add(reverseHex(toHex(array[32, byte](txid))))
    return %txids

proc handleGetMempoolEntry(rpc: RpcServer, params: JsonNode): JsonNode =
  ## getmempoolentry txid
  ## Returns mempool data for a given transaction.
  ## Reference: Bitcoin Core rpc/mempool.cpp getmempoolentry / entryToJSON.
  ## W70d: was duplicating mempoolEntryJson inline (with a dead feeRate var);
  ## now calls the shared helper.
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing txid parameter")

  # Core ParseHashV (mempool.cpp:844, name "txid"): a malformed txid is
  # RPC_INVALID_PARAMETER (-8) at the parse boundary. A well-formed-but-absent
  # txid still yields the -5 "Transaction not in mempool" below.
  validateHashV(params[0].getStr(), "txid")
  let txid = parseTxidParam(params[0].getStr())
  let entryOpt = rpc.mempool.get(txid)

  if entryOpt.isNone:
    raise newRpcError(RpcInvalidAddressOrKey, "Transaction not in mempool")

  mempoolEntryJson(rpc, txid, entryOpt.get())

proc handleGetMempoolAncestors(rpc: RpcServer, params: JsonNode): JsonNode =
  ## getmempoolancestors txid [verbose=false]
  ## If txid is in the mempool, returns all in-mempool ancestors.
  ## Reference: bitcoin-core/src/rpc/mempool.cpp getmempoolancestors
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing txid parameter")

  let txid = parseTxidParam(params[0].getStr())
  let verbose = params.len >= 2 and params[1].kind == JBool and params[1].getBool()

  let entryOpt = rpc.mempool.get(txid)
  if entryOpt.isNone:
    raise newRpcError(RpcInvalidAddressOrKey, "Transaction not in mempool")

  let entry = entryOpt.get()
  let ancestors = rpc.mempool.calculateAncestors(entry.tx)

  if not verbose:
    var arr = newJArray()
    for a in ancestors:
      arr.add(%reverseHex(toHex(array[32, byte](a))))
    return arr
  else:
    var obj = newJObject()
    for a in ancestors:
      let aOpt = rpc.mempool.get(a)
      if aOpt.isSome:
        obj[reverseHex(toHex(array[32, byte](a)))] =
          mempoolEntryJson(rpc, a, aOpt.get())
    return obj

proc handleGetMempoolDescendants(rpc: RpcServer, params: JsonNode): JsonNode =
  ## getmempooldescendants txid [verbose=false]
  ## If txid is in the mempool, returns all in-mempool descendants.
  ## Reference: bitcoin-core/src/rpc/mempool.cpp getmempooldescendants
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing txid parameter")

  let txid = parseTxidParam(params[0].getStr())
  let verbose = params.len >= 2 and params[1].kind == JBool and params[1].getBool()

  if rpc.mempool.get(txid).isNone:
    raise newRpcError(RpcInvalidAddressOrKey, "Transaction not in mempool")

  let descendants = rpc.mempool.calculateDescendants(txid)

  if not verbose:
    var arr = newJArray()
    for d in descendants:
      arr.add(%reverseHex(toHex(array[32, byte](d))))
    return arr
  else:
    var obj = newJObject()
    for d in descendants:
      let dOpt = rpc.mempool.get(d)
      if dOpt.isSome:
        obj[reverseHex(toHex(array[32, byte](d)))] =
          mempoolEntryJson(rpc, d, dOpt.get())
    return obj

proc handleDumpMempool(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Dumps the mempool to mempool.dat in the data directory.
  ## Bitcoin Core compatible (rpc/mempool.cpp dumpmempool).
  ##
  ## Optional second positional param is a target filename. We resolve it
  ## relative to the rpc-server-known data directory; if omitted, default
  ## to <network-datadir>/mempool.dat. The path is also returned.
  if rpc.mempool == nil:
    raise newRpcError(RpcInternalError, "Mempool unavailable")
  # We don't track the data directory on RpcServer directly, so accept a
  # filename param (matches Core's optional first arg) or fall back to
  # the cwd. nimrod typically launches with cwd = data dir, so this is OK
  # for now; the server-side persistent dump is wired in the shutdown path.
  var path = CurrentMempoolDumpFile
  if params.len >= 1 and params[0].kind == JString:
    path = params[0].getStr()

  let ok = dumpMempool(rpc.mempool, path)
  if not ok:
    raise newRpcError(RpcInternalError, "dumpmempool failed (see node log)")
  %*{ "filename": path }

proc handleLoadMempool(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Loads mempool.dat into the running mempool. Bitcoin Core compatible.
  if rpc.mempool == nil:
    raise newRpcError(RpcInternalError, "Mempool unavailable")
  var path = CurrentMempoolDumpFile
  if params.len >= 1 and params[0].kind == JString:
    path = params[0].getStr()

  let r = loadMempool(rpc.mempool, path, rpc.crypto)
  if r.isNone:
    raise newRpcError(RpcInternalError,
      "loadmempool: " & path & " not found or unreadable")
  let counts = r.get()
  %*{
    "succeeded":    counts.succeeded,
    "failed":       counts.failed,
    "expired":      counts.expired,
    "alreadythere": counts.alreadyThere
  }

proc orphanToJson(rpc: RpcServer, entry: OrphanEntry): JsonNode =
  ## Build the verbosity>=1 per-orphan object for getorphantxs.
  ## Mirrors bitcoin-core/src/rpc/mempool.cpp OrphanToJSON / OrphanDescription
  ## EXACTLY (verified against rpc/mempool.cpp:1217-1231), in this field order:
  ##   txid, wtxid, bytes (ComputeTotalSize), vsize (BIP141), weight (BIP141),
  ##   from (array of announcing peers).
  ## There is NO `expiration` field in Core's OrphanToJSON — do not add one.
  ##
  ## Notes vs Core:
  ##  - `bytes` = entry.size, which addOrphan stored as the with-witness
  ##    serialized length (Core: CTransaction::ComputeTotalSize()).
  ##  - `vsize` / `weight` are computed exactly like getrawtransaction /
  ##    getmempoolentry: weight via calculateTransactionWeight, vsize = ceil(weight/4).
  ##  - `from` is Core's array of numeric peer ids. nimrod's orphan pool keys
  ##    announcers by (address, port) rather than a numeric NodeId, so we emit a
  ##    1-element array of "address:port". A blank announcer (address == "" and
  ##    port == 0) yields an empty array. The pool tracks a single announcer per
  ##    orphan today, so the array is at most one element.
  let txid = entry.txid
  let wtxid = entry.wtxid
  let weight = validation.calculateTransactionWeight(entry.tx)
  let vsize = (weight + 3) div 4

  result = %*{
    "txid": reverseHex(toHex(array[32, byte](txid))),
    "wtxid": reverseHex(toHex(array[32, byte](wtxid))),
    "bytes": entry.size,
    "vsize": vsize,
    "weight": weight
  }

  var fromArr = newJArray()
  # Empty / sentinel announcer → empty array (best-effort, see from_peer_source).
  if not (entry.fromPeer.address.len == 0 and entry.fromPeer.port == 0'u16):
    fromArr.add(%(entry.fromPeer.address & ":" & $entry.fromPeer.port))
  result["from"] = fromArr

proc handleGetTxSpendingPrevout(rpc: RpcServer, params: JsonNode): JsonNode =
  ## gettxspendingprevout [{"txid","vout"},...] ( {options} )
  ##
  ## Scans the mempool (and the txospenderindex, if available) to find
  ## transactions spending any of the given outputs.  Byte-faithful to Bitcoin
  ## Core (bitcoin-core/src/rpc/mempool.cpp::gettxspendingprevout):
  ##
  ##   params[0] outputs  ARR of {txid (str), vout (num)}.  Empty -> error -8
  ##                      "Invalid parameter, outputs are missing".  Negative
  ##                      vout -> error -8 "Invalid parameter, vout cannot be
  ##                      negative".  Strict object: unknown keys / missing
  ##                      txid|vout rejected.
  ##   params[1] options  OBJ {mempool_only (bool, default: true iff index
  ##                      unavailable), return_spending_tx (bool, default
  ##                      false)}.  Strict: unknown keys rejected.
  ##
  ## Algorithm: search the mempool reverse-index first; if mempool_only OR the
  ## spend was resolved in the mempool, done.  Otherwise the request requires
  ## the index: if it is unavailable, error -1 "Mempool lacks a relevant spend,
  ## and txospenderindex is unavailable."; else look each remaining outpoint up
  ## in the index.  Output pushKV order per entry: txid, vout,
  ## spendingtxid (if found), spendingtx (iff return_spending_tx, full hex),
  ## blockhash (CONFIRMED / index path ONLY).  An unspent outpoint yields the
  ## bare {txid, vout}.

  # --- params[0]: outputs array (required, non-empty) ---
  if params.len < 1 or params[0].kind != JArray:
    raise newRpcError(RpcInvalidParameter, "Invalid parameter, outputs are missing")
  let outputParams = params[0]
  if outputParams.len == 0:
    raise newRpcError(RpcInvalidParameter, "Invalid parameter, outputs are missing")

  # --- params[1]: options object (optional, strict) ---
  let options =
    if params.len >= 2 and params[1].kind != JNull: params[1]
    else: newJObject()
  if options.kind != JObject:
    raise newRpcError(RpcTypeError, "Expected type object for options")
  for k, v in options:
    if k notin ["mempool_only", "return_spending_tx"]:
      raise newRpcError(RpcInvalidParameter, "Unexpected key " & k)
    if v.kind != JBool:
      raise newRpcError(RpcTypeError, "Expected type bool for " & k)

  let indexAvailable = rpc.txoSpenderIndex != nil and rpc.txoSpenderIndex.enabled
  let mempoolOnly =
    if options.hasKey("mempool_only"): options["mempool_only"].getBool()
    else: not indexAvailable
  let returnSpendingTx =
    if options.hasKey("return_spending_tx"): options["return_spending_tx"].getBool()
    else: false

  # --- Parse + validate every requested outpoint up front (Core builds the
  #     full worklist before touching the mempool). ---
  type Prevout = object
    outpoint: OutPoint
    txidHex: string
    vout: int
  var prevouts: seq[Prevout]
  for o in outputParams:
    if o.kind != JObject:
      raise newRpcError(RpcTypeError, "Expected type object")
    # Strict: only txid + vout permitted; both required.
    for k, _ in o:
      if k notin ["txid", "vout"]:
        raise newRpcError(RpcInvalidParameter, "Unexpected key " & k)
    if not o.hasKey("txid") or o["txid"].kind != JString:
      raise newRpcError(RpcInvalidParameter, "Missing txid")
    if not o.hasKey("vout") or o["vout"].kind != JInt:
      raise newRpcError(RpcInvalidParameter, "Missing vout")
    let txidHex = o["txid"].getStr()
    let txid = parseTxidParam(txidHex)  # validates 64-hex, throws -5 otherwise
    let nOutput = o["vout"].getInt()
    if nOutput < 0:
      raise newRpcError(RpcInvalidParameter, "Invalid parameter, vout cannot be negative")
    prevouts.add(Prevout(
      outpoint: OutPoint(txid: txid, vout: uint32(nOutput)),
      txidHex: txidHex,
      vout: nOutput))

  result = newJArray()

  # Build the per-entry JSON object.  spendingTxOpt non-nil => spent (push
  # spendingtxid, and the full hex iff return_spending_tx).
  proc makeOutput(p: Prevout, spendingTx: Option[Transaction]): JsonNode =
    var o = newJObject()
    o["txid"] = %p.txidHex
    o["vout"] = %p.vout
    if spendingTx.isSome:
      let stx = spendingTx.get()
      o["spendingtxid"] = %reverseHex(toHex(array[32, byte](txid(stx))))
      if returnSpendingTx:
        o["spendingtx"] = %toHex(serialize(stx))
    o

  # --- Phase 1: search the mempool reverse-index first. ---
  var remaining: seq[Prevout]
  for p in prevouts:
    let spenderOpt = rpc.mempool.getSpender(p.outpoint)
    if spenderOpt.isNone and not mempoolOnly:
      # Not spent in the mempool and we may consult the index: defer.
      remaining.add(p)
      continue
    # Either spent in the mempool, or this is a mempool_only request (so the
    # mempool answer — possibly "unspent" — is final).
    var spendingTx = none(Transaction)
    if spenderOpt.isSome:
      spendingTx = rpc.mempool.getTransaction(spenderOpt.get())
    result.add(makeOutput(p, spendingTx))

  # All handled by the mempool search (or mempool_only) — return early.
  if remaining.len == 0:
    return result

  # --- Phase 2: index path.  Some outpoints are unresolved and this was not a
  #     mempool_only request, so the index is required. ---
  if not indexAvailable:
    raise newRpcError(RpcMiscError,
      "Mempool lacks a relevant spend, and txospenderindex is unavailable.")

  for p in remaining:
    let recOpt = rpc.txoSpenderIndex.findSpender(p.outpoint)
    if recOpt.isSome:
      let rec = recOpt.get()
      # Decode the stored spending tx so makeOutput can emit spendingtxid /
      # spendingtx consistently with the mempool path.
      var stx: Transaction
      var decoded = false
      try:
        stx = deserializeTransaction(rec.spendingTx)
        decoded = true
      except CatchableError:
        decoded = false
      var o = makeOutput(p, if decoded: some(stx) else: none(Transaction))
      if not decoded:
        # Fall back to the stored txid if the body failed to decode.
        o["spendingtxid"] = %reverseHex(toHex(array[32, byte](rec.spendingTxid)))
      # blockhash is emitted ONLY on the confirmed/index path.
      o["blockhash"] = %reverseHex(toHex(array[32, byte](rec.blockHash)))
      result.add(o)
    else:
      # Unspent on-chain: bare {txid, vout}.
      result.add(makeOutput(p, none(Transaction)))

  return result

proc handleGetOrphanTxs(rpc: RpcServer, params: JsonNode): JsonNode =
  ## getorphantxs ( verbosity )
  ## Shows transactions in the tx orphanage. EXPERIMENTAL (mirrors Core v28+).
  ## Reference: bitcoin-core/src/rpc/mempool.cpp getorphantxs.
  ##   verbosity 0 → array of txid strings (Core: orphan.tx->GetHash(), the
  ##                 NON-witness txid; "may contain duplicates")
  ##   verbosity 1 → array of { txid, wtxid, bytes, vsize, weight, from }
  ##   verbosity 2 → verbosity-1 objects PLUS "hex" (serialized, hex-encoded tx)
  ## Out-of-range verbosity → RPC_INVALID_PARAMETER (-8) with Core's message.

  # Parse optional verbosity (default 0). Core: ParseVerbosity(..., default=0,
  # allow_bool=false), so a BOOLEAN argument must be REJECTED (not mapped to
  # 0/1). We accept only a JSON integer; any other kind (including JBool)
  # raises an error, matching allow_bool=false.
  var verbosity = 0
  if params.len >= 1 and params[0].kind != JNull:
    if params[0].kind == JInt:
      verbosity = params[0].getInt()
    else:
      raise newRpcError(RpcInvalidParameter,
        "JSON value of type " & $params[0].kind & " is not of expected type number")

  if verbosity < 0 or verbosity > 2:
    raise newRpcError(RpcInvalidParameter,
      "Invalid verbosity value " & $verbosity)

  var ret = newJArray()
  if rpc.orphanPool == nil:
    return ret  # No orphanage wired (test rig / pre-startup): empty array.

  if verbosity == 0:
    # Array of orphan txids. Core pushes orphan.tx->GetHash().ToString(), the
    # NON-witness txid (help: "0 for an array of txids (may contain
    # duplicates)"). The orphanage is keyed by wtxid, but the emitted value is
    # the txid, so iterate entries and emit entry.txid (NOT the wtxid key).
    for wtxid, entry in rpc.orphanPool.entries:
      ret.add(%reverseHex(toHex(array[32, byte](entry.txid))))
  elif verbosity == 1:
    for wtxid, entry in rpc.orphanPool.entries:
      ret.add(orphanToJson(rpc, entry))
  else:  # verbosity == 2
    for wtxid, entry in rpc.orphanPool.entries:
      var o = orphanToJson(rpc, entry)
      o["hex"] = %toHex(serialize(entry.tx, includeWitness = true))
      ret.add(o)

  ret

proc handlePrioritiseTransaction(rpc: RpcServer, params: JsonNode): JsonNode =
  ## prioritisetransaction "txid" ( dummy ) fee_delta
  ## Accepts the transaction into mined blocks at a higher (or lower) priority
  ## by recording a signed fee delta that block selection treats as if the tx
  ## had paid that much more (or less) absolute fee.
  ## Reference: bitcoin-core/src/rpc/mining.cpp prioritisetransaction.
  ##
  ## Args (positional, Core order): txid, dummy, fee_delta.
  ##   - dummy is a legacy priority argument: it MUST be 0 or null/omitted; a
  ##     non-zero value is rejected (Core: RPC_INVALID_PARAMETER).
  ##   - fee_delta is a SATOSHI value (NOT a fee rate), required.
  ## The delta STACKS additively onto any previously set delta; a net delta of
  ## 0 erases the entry (handled in mempool.prioritiseTransaction).
  if rpc.mempool == nil:
    raise newRpcError(RpcInternalError, "Mempool unavailable")
  if params.len < 1 or params[0].kind != JString:
    raise newRpcError(RpcInvalidParams, "missing txid parameter")

  let txid = parseTxidParam(params[0].getStr())

  # dummy (legacy priority): index 1. Must be 0 or null/omitted. Core uses
  # MaybeArg<double>, so a JSON int or float both count; only a NON-zero
  # value is an error.
  if params.len >= 2 and params[1].kind != JNull:
    var dummyVal = 0.0
    case params[1].kind
    of JInt:   dummyVal = float64(params[1].getBiggestInt())
    of JFloat: dummyVal = params[1].getFloat()
    else:
      raise newRpcError(RpcInvalidParameter,
        "Priority is no longer supported, dummy argument to prioritisetransaction must be 0.")
    if dummyVal != 0.0:
      raise newRpcError(RpcInvalidParameter,
        "Priority is no longer supported, dummy argument to prioritisetransaction must be 0.")

  # fee_delta (satoshis, signed): index 2, required. Core: request.params[2]
  # .getInt<int64_t>().
  if params.len < 3 or params[2].kind != JInt:
    raise newRpcError(RpcInvalidParameter,
      "fee_delta must be an integer number of satoshis")
  let feeDelta = params[2].getBiggestInt()

  # Core: non-0 fee dust transactions are not allowed for entry, and
  # modification is not allowed afterwards (require_standard + tx in mempool +
  # any dust output). nimrod's mempool enforces standardness, so apply the
  # same guard when the tx is present in the mempool.
  let entryOpt = rpc.mempool.get(txid)
  if entryOpt.isSome:
    for output in entryOpt.get().tx.outputs:
      if isDust(output):
        raise newRpcError(RpcInvalidParameter,
          "Priority is not supported for transactions with dust outputs.")

  rpc.mempool.prioritiseTransaction(txid, feeDelta)
  %true

proc handleGetPrioritisedTransactions(rpc: RpcServer, params: JsonNode): JsonNode =
  ## getprioritisedtransactions
  ## Returns a map of all user-created (see prioritisetransaction) fee deltas
  ## by txid, and whether the tx is present in mempool.
  ## Reference: bitcoin-core/src/rpc/mining.cpp getprioritisedtransactions.
  ##
  ## Shape (byte-exact with Core): a JSON object keyed by txid (display hex);
  ## each value = { fee_delta: <i64>, in_mempool: <bool>,
  ##                modified_fee: <i64, ONLY when in_mempool=true> }.
  if rpc.mempool == nil:
    raise newRpcError(RpcInternalError, "Mempool unavailable")
  var ret = newJObject()
  for info in rpc.mempool.getPrioritisedTransactions():
    var inner = newJObject()
    inner["fee_delta"] = %info.delta
    inner["in_mempool"] = %info.inMempool
    if info.inMempool:
      inner["modified_fee"] = %info.modifiedFee
    ret[reverseHex(toHex(array[32, byte](info.txid)))] = inner
  ret

# Raw transaction RPCs

# Script type detection and address extraction for verbose output
proc getScriptType(script: seq[byte]): string =
  ## Detect script type for verbose output
  if script.len == 0:
    return "nonstandard"

  # P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
  if script.len == 25 and script[0] == 0x76 and script[1] == 0xa9 and
     script[2] == 0x14 and script[23] == 0x88 and script[24] == 0xac:
    return "pubkeyhash"

  # P2SH: OP_HASH160 <20 bytes> OP_EQUAL
  if script.len == 23 and script[0] == 0xa9 and script[1] == 0x14 and
     script[22] == 0x87:
    return "scripthash"

  # P2WPKH: OP_0 <20 bytes>
  if script.len == 22 and script[0] == 0x00 and script[1] == 0x14:
    return "witness_v0_keyhash"

  # P2WSH: OP_0 <32 bytes>
  if script.len == 34 and script[0] == 0x00 and script[1] == 0x20:
    return "witness_v0_scripthash"

  # P2TR: OP_1 <32 bytes>
  if script.len == 34 and script[0] == 0x51 and script[1] == 0x20:
    return "witness_v1_taproot"

  # P2A (Pay-to-Anchor): OP_1 <0x4e73>
  if script.len == 4 and script[0] == 0x51 and script[1] == 0x02 and
     script[2] == 0x4e and script[3] == 0x73:
    return "anchor"

  # P2PK: <33 or 65 bytes pubkey> OP_CHECKSIG
  if script.len >= 35 and script[^1] == 0xac:
    let pushLen = script[0]
    if (pushLen == 33 or pushLen == 65) and script.len == int(pushLen) + 2:
      return "pubkey"

  # OP_RETURN: null data — Core requires IsPushOnly(begin()+1) too.
  # A script starting with OP_RETURN but containing a truncated push
  # (e.g. trailing bytes where pushLen > remaining) is NONSTANDARD.
  if script.len >= 1 and script[0] == 0x6a:
    # Verify that bytes [1..] form a valid push-only sequence (all opcodes <= 0x60
    # and all data pushes well-formed). Mirrors CScript::IsPushOnly.
    block checkPushOnly:
      var j = 1
      while j < script.len:
        let op = int(script[j])
        if op >= 0x01 and op <= 0x4b:
          # Direct push: need op more bytes
          if j + 1 + op > script.len:
            break checkPushOnly  # truncated → nonstandard
          j += 1 + op
        elif op == 0x4c:  # OP_PUSHDATA1
          if j + 1 >= script.len:
            break checkPushOnly
          let dlen = int(script[j + 1])
          if j + 2 + dlen > script.len:
            break checkPushOnly
          j += 2 + dlen
        elif op == 0x4d:  # OP_PUSHDATA2
          if j + 2 >= script.len:
            break checkPushOnly
          let dlen = int(script[j + 1]) or (int(script[j + 2]) shl 8)
          if j + 3 + dlen > script.len:
            break checkPushOnly
          j += 3 + dlen
        elif op == 0x4e:  # OP_PUSHDATA4
          if j + 4 >= script.len:
            break checkPushOnly
          let dlen = int(script[j + 1]) or (int(script[j + 2]) shl 8) or
                     (int(script[j + 3]) shl 16) or (int(script[j + 4]) shl 24)
          if j + 5 + dlen > script.len:
            break checkPushOnly
          j += 5 + dlen
        elif op <= 0x60:
          # OP_0 (0x00) through OP_16 (0x60): valid push opcodes
          j += 1
        else:
          # opcode > OP_16 → not push-only → nonstandard
          break checkPushOnly
      return "nulldata"  # all bytes valid push-only

  # Multisig: OP_M <pubkeys> OP_N OP_CHECKMULTISIG
  if script.len >= 4 and script[^1] == 0xae:
    let opM = script[0]
    let opN = script[^2]
    if opM >= 0x51 and opM <= 0x60 and opN >= 0x51 and opN <= 0x60:
      return "multisig"

  return "nonstandard"

proc extractAddressFromScript(script: seq[byte], mainnet: bool,
                              regtest: bool = false): Option[string] =
  ## Extract address from scriptPubKey if possible.
  ##
  ## `regtest` selects the "bcrt" bech32 HRP for segwit addresses; without it
  ## regtest segwit addresses collapse onto the shared testnet "tb" HRP. It
  ## defaults to false so the many non-regtest callers are unaffected.
  let scriptType = getScriptType(script)

  case scriptType
  of "pubkeyhash":
    # P2PKH: extract 20-byte hash
    var hash: array[20, byte]
    for i in 0 ..< 20:
      hash[i] = script[3 + i]
    let addrVal = Address(kind: P2PKH, pubkeyHash: hash)
    return some(encodeAddress(addrVal, mainnet, regtest))

  of "scripthash":
    # P2SH: extract 20-byte hash
    var hash: array[20, byte]
    for i in 0 ..< 20:
      hash[i] = script[2 + i]
    let addrVal = Address(kind: P2SH, scriptHash: hash)
    return some(encodeAddress(addrVal, mainnet, regtest))

  of "witness_v0_keyhash":
    # P2WPKH: extract 20-byte hash
    var hash: array[20, byte]
    for i in 0 ..< 20:
      hash[i] = script[2 + i]
    let addrVal = Address(kind: P2WPKH, wpkh: hash)
    return some(encodeAddress(addrVal, mainnet, regtest))

  of "witness_v0_scripthash":
    # P2WSH: extract 32-byte hash
    var hash: array[32, byte]
    for i in 0 ..< 32:
      hash[i] = script[2 + i]
    let addrVal = Address(kind: P2WSH, wsh: hash)
    return some(encodeAddress(addrVal, mainnet, regtest))

  of "witness_v1_taproot":
    # P2TR: extract 32-byte x-only pubkey
    var key: array[32, byte]
    for i in 0 ..< 32:
      key[i] = script[2 + i]
    let addrVal = Address(kind: P2TR, taprootKey: key)
    return some(encodeAddress(addrVal, mainnet, regtest))

  else:
    return none(string)

proc disassembleScript(script: seq[byte]): string =
  ## Disassemble script to human-readable asm format
  var result = ""
  var i = 0

  while i < script.len:
    if result.len > 0:
      result.add(" ")

    let op = script[i]

    # Push data opcodes (1-75 bytes)
    if op >= 0x01 and op <= 0x4b:
      let dataLen = int(op)
      if i + 1 + dataLen <= script.len:
        var data = ""
        for j in 0 ..< dataLen:
          data.add(toHex(script[i + 1 + j], 2).toLowerAscii())
        result.add(data)
        i += 1 + dataLen
      else:
        result.add("[error]")
        break
    elif op == 0x4c:  # OP_PUSHDATA1
      if i + 1 < script.len:
        let dataLen = int(script[i + 1])
        if i + 2 + dataLen <= script.len:
          var data = ""
          for j in 0 ..< dataLen:
            data.add(toHex(script[i + 2 + j], 2).toLowerAscii())
          result.add(data)
          i += 2 + dataLen
        else:
          result.add("[error]")
          break
      else:
        result.add("[error]")
        break
    elif op == 0x4d:  # OP_PUSHDATA2
      if i + 2 < script.len:
        let dataLen = int(script[i + 1]) or (int(script[i + 2]) shl 8)
        if i + 3 + dataLen <= script.len:
          var data = ""
          for j in 0 ..< dataLen:
            data.add(toHex(script[i + 3 + j], 2).toLowerAscii())
          result.add(data)
          i += 3 + dataLen
        else:
          result.add("[error]")
          break
      else:
        result.add("[error]")
        break
    elif op == 0x4e:  # OP_PUSHDATA4
      if i + 4 < script.len:
        let dataLen = int(script[i + 1]) or (int(script[i + 2]) shl 8) or
                      (int(script[i + 3]) shl 16) or (int(script[i + 4]) shl 24)
        if i + 5 + dataLen <= script.len:
          var data = ""
          for j in 0 ..< dataLen:
            data.add(toHex(script[i + 5 + j], 2).toLowerAscii())
          result.add(data)
          i += 5 + dataLen
        else:
          result.add("[error]")
          break
      else:
        result.add("[error]")
        break
    else:
      # Map opcode to name
      let opName = case op
        of 0x00: "0"
        of 0x4f: "-1"
        of 0x51: "1"
        of 0x52: "2"
        of 0x53: "3"
        of 0x54: "4"
        of 0x55: "5"
        of 0x56: "6"
        of 0x57: "7"
        of 0x58: "8"
        of 0x59: "9"
        of 0x5a: "10"
        of 0x5b: "11"
        of 0x5c: "12"
        of 0x5d: "13"
        of 0x5e: "14"
        of 0x5f: "15"
        of 0x60: "16"
        of 0x61: "OP_NOP"
        of 0x63: "OP_IF"
        of 0x64: "OP_NOTIF"
        of 0x67: "OP_ELSE"
        of 0x68: "OP_ENDIF"
        of 0x69: "OP_VERIFY"
        of 0x6a: "OP_RETURN"
        of 0x6b: "OP_TOALTSTACK"
        of 0x6c: "OP_FROMALTSTACK"
        of 0x6d: "OP_2DROP"
        of 0x6e: "OP_2DUP"
        of 0x6f: "OP_3DUP"
        of 0x70: "OP_2OVER"
        of 0x71: "OP_2ROT"
        of 0x72: "OP_2SWAP"
        of 0x73: "OP_IFDUP"
        of 0x74: "OP_DEPTH"
        of 0x75: "OP_DROP"
        of 0x76: "OP_DUP"
        of 0x77: "OP_NIP"
        of 0x78: "OP_OVER"
        of 0x79: "OP_PICK"
        of 0x7a: "OP_ROLL"
        of 0x7b: "OP_ROT"
        of 0x7c: "OP_SWAP"
        of 0x7d: "OP_TUCK"
        of 0x82: "OP_SIZE"
        of 0x87: "OP_EQUAL"
        of 0x88: "OP_EQUALVERIFY"
        of 0x8b: "OP_1ADD"
        of 0x8c: "OP_1SUB"
        of 0x8f: "OP_NEGATE"
        of 0x90: "OP_ABS"
        of 0x91: "OP_NOT"
        of 0x92: "OP_0NOTEQUAL"
        of 0x93: "OP_ADD"
        of 0x94: "OP_SUB"
        of 0x9a: "OP_BOOLAND"
        of 0x9b: "OP_BOOLOR"
        of 0x9c: "OP_NUMEQUAL"
        of 0x9d: "OP_NUMEQUALVERIFY"
        of 0x9e: "OP_NUMNOTEQUAL"
        of 0x9f: "OP_LESSTHAN"
        of 0xa0: "OP_GREATERTHAN"
        of 0xa1: "OP_LESSTHANOREQUAL"
        of 0xa2: "OP_GREATERTHANOREQUAL"
        of 0xa3: "OP_MIN"
        of 0xa4: "OP_MAX"
        of 0xa5: "OP_WITHIN"
        of 0xa6: "OP_RIPEMD160"
        of 0xa7: "OP_SHA1"
        of 0xa8: "OP_SHA256"
        of 0xa9: "OP_HASH160"
        of 0xaa: "OP_HASH256"
        of 0xab: "OP_CODESEPARATOR"
        of 0xac: "OP_CHECKSIG"
        of 0xad: "OP_CHECKSIGVERIFY"
        of 0xae: "OP_CHECKMULTISIG"
        of 0xaf: "OP_CHECKMULTISIGVERIFY"
        of 0xb0: "OP_NOP1"
        of 0xb1: "OP_CHECKLOCKTIMEVERIFY"
        of 0xb2: "OP_CHECKSEQUENCEVERIFY"
        of 0xb3: "OP_NOP4"
        of 0xb4: "OP_NOP5"
        of 0xb5: "OP_NOP6"
        of 0xb6: "OP_NOP7"
        of 0xb7: "OP_NOP8"
        of 0xb8: "OP_NOP9"
        of 0xb9: "OP_NOP10"
        of 0xba: "OP_CHECKSIGADD"
        else: "OP_UNKNOWN[" & toHex(op, 2) & "]"
      result.add(opName)
      i += 1

  return result

proc rawNumberNode*(s: string): JsonNode =
  ## Construct a JsonNode that serializes as a raw (unquoted) numeric token.
  ##
  ## Nim's stdlib `JFloat` formats whole-BTC values as `1.0`, which differs
  ## from Bitcoin Core's `ValueFromAmount` (which always emits `%d.%08d`,
  ## e.g. `1.00000000`) and breaks `decodepsbt` byte-identity vs Core
  ## (W50 diagnostic, W51).
  ##
  ## `parseJson` with `rawFloats = true` constructs a `JString` with the
  ## stdlib's internal `isUnquoted` flag set; that flag tells `toUgly` /
  ## `$` to emit the string back without quotes — preserving the exact
  ## decimal text we hand it. We use that as a stdlib-supported route to
  ## the otherwise-unexported "raw number" node kind.
  ##
  ## Reference: bitcoin-core/src/core_io.cpp `ValueFromAmount`.
  var st = newStringStream(s)
  result = parseJson(st, "rawnum", false, true)

proc formatBitcoinAmount*(sats: int64): string =
  ## Format a satoshi amount the way Bitcoin Core's `ValueFromAmount`
  ## (core_io.cpp:285) does: `%s%d.%08d`. Always 8 fractional digits, no
  ## scientific notation, sign on the whole part.
  let neg = sats < 0
  let abs = if neg: -sats else: sats
  let whole = abs div 100_000_000'i64
  let frac = abs mod 100_000_000'i64
  result = (if neg: "-" else: "") & $whole & "." & align($frac, 8, '0')

proc btcAmountNode*(sats: int64): JsonNode =
  ## Emit a satoshi amount as a Core-shaped raw JSON number
  ## (e.g. `1.00000000`, never `1.0`). See `formatBitcoinAmount` +
  ## `rawNumberNode` for details.
  rawNumberNode(formatBitcoinAmount(sats))

proc inferAddrDescriptor*(script: seq[byte], mainnet: bool,
                          regtest: bool = false): string =
  ## Build a BIP-380 descriptor string for a scriptPubKey, mirroring Core's
  ## `InferDescriptor` (script/descriptor.cpp:2897) when called without a
  ## SigningProvider that has the keys (which is the case for `decodepsbt`).
  ##
  ## Cases (in InferScript priority order):
  ##   - witness_v1_taproot (OP_1 <32-byte x-only key>) → rawtr(<hex>)
  ##   - bare multisig (OP_m <keys> OP_n OP_CHECKMULTISIG) → multi(m, key1, ...)
  ##   - any script with an extractable address → addr(<address>)
  ##   - everything else → raw(<hex>)
  ##
  ## Reference: bitcoin-core/src/script/descriptor.cpp InferScript lines 2732-2744.
  let scriptType = getScriptType(script)
  let payload =
    if scriptType == "witness_v1_taproot" and script.len == 34:
      # Extract the 32-byte x-only pubkey (bytes 2..33) and emit rawtr(<hex>)
      let xonlyHex = toHex(script[2 ..< 34])
      "rawtr(" & xonlyHex & ")"
    elif scriptType == "multisig" and script.len >= 4 and script[^1] == 0xae:
      # Bare multisig: parse threshold and pubkeys, emit multi(m, key1, ...).
      # Reference: bitcoin-core/src/script/descriptor.cpp InferScript line 2732.
      # Script format: OP_M <push><pubkey1> ... <push><pubkeyN> OP_N OP_CHECKMULTISIG
      let opM = script[0]
      let m =
        if opM == 0x00: 0           # OP_0
        elif opM >= 0x51 and opM <= 0x60: int(opM) - 0x50  # OP_1..OP_16
        else: -1
      if m < 0:
        "raw(" & toHex(script) & ")"
      else:
        var keys: seq[string]
        var i = 1
        var ok = true
        while i < script.len - 2:  # stop before OP_N OP_CHECKMULTISIG
          let pushLen = int(script[i])
          if pushLen == 0: break
          if i + 1 + pushLen > script.len - 2:
            ok = false; break
          keys.add(toHex(script[i + 1 ..< i + 1 + pushLen]))
          i += 1 + pushLen
        if not ok or keys.len == 0:
          "raw(" & toHex(script) & ")"
        else:
          var parts = @[$m]
          parts.add(keys)
          "multi(" & parts.join(",") & ")"
    else:
      let addrOpt = extractAddressFromScript(script, mainnet, regtest)
      if addrOpt.isSome:
        "addr(" & addrOpt.get() & ")"
      else:
        "raw(" & toHex(script) & ")"
  try:
    addDescriptorChecksum(payload)
  except DescriptorError:
    # Defensive: address/hex chars are always inside the descriptor input
    # charset, so this path is unreachable for well-formed inputs.
    payload

proc buildScriptPubKeyJson(script: seq[byte], mainnet: bool,
                           regtest: bool = false): JsonNode =
  ## Build scriptPubKey JSON object with type, asm, hex, address, desc.
  ##
  ## Reference: bitcoin-core/src/core_io.cpp `ScriptToUniv` /
  ## `ScriptPubKeyToUniv`. Core unconditionally emits a `desc` key carrying
  ## `InferDescriptor(...).ToString()` plus its 8-char BIP-380 checksum
  ## (rpc/rawtransaction.cpp `decodepsbt`); without a key provider this
  ## resolves to `addr(<address>)#<csum>` for standard scripts and
  ## `raw(<hex>)#<csum>` otherwise. W51: closes the SHAPE-MISSING `desc`
  ## gap surfaced by W50.
  let scriptType = getScriptType(script)
  let addrOpt = extractAddressFromScript(script, mainnet, regtest)

  # Core ScriptToUniv (core_io.cpp) key order: asm, desc, hex, address, type.
  # Build incrementally so `address` is emitted BEFORE `type`.
  result = %*{
    "asm": disassembleScript(script),
    "desc": inferAddrDescriptor(script, mainnet, regtest),
    "hex": toHex(script)
  }

  if addrOpt.isSome:
    result["address"] = %addrOpt.get()

  result["type"] = %scriptType

proc buildVinJson(tx: Transaction, inputIndex: int): JsonNode =
  ## Build vin JSON object for an input
  let inp = tx.inputs[inputIndex]
  let isCoinbase = inp.prevOut.txid == TxId(default(array[32, byte])) and
                   inp.prevOut.vout == 0xFFFFFFFF'u32

  # Core (core_io.cpp TxToUniv) pushes keys in the order:
  #   coinbase | (txid, vout, scriptSig), then txinwitness (if any), then sequence.
  # i.e. txinwitness comes BEFORE sequence, so build the object incrementally
  # to preserve that key order.
  if isCoinbase:
    result = %*{
      "coinbase": toHex(inp.scriptSig)
    }
  else:
    result = %*{
      "txid": reverseHex(toHex(array[32, byte](inp.prevOut.txid))),
      "vout": inp.prevOut.vout,
      "scriptSig": %*{
        "asm": disassembleScriptSigAsmStr(inp.scriptSig),
        "hex": toHex(inp.scriptSig)
      }
    }

  # Add witness data if present (BEFORE sequence, per Core key order).
  if tx.witnesses.len > inputIndex and tx.witnesses[inputIndex].len > 0:
    var txinwitness = newJArray()
    for item in tx.witnesses[inputIndex]:
      txinwitness.add(%toHex(item))
    result["txinwitness"] = txinwitness

  result["sequence"] = %inp.sequence

proc buildVoutJson(output: TxOut, index: int, mainnet: bool,
                   regtest: bool = false): JsonNode =
  ## Build vout JSON object for an output. `value` is emitted as Core-shaped
  ## fixed 8-decimal text (`%d.%08d`, see `btcAmountNode`) so that
  ## whole-BTC amounts read `1.00000000` not Nim's `1.0` (W50 / W51).
  ## `regtest` selects the "bcrt" bech32 HRP for the scriptPubKey.address.
  %*{
    "value": btcAmountNode(int64(output.value)),
    "n": index,
    "scriptPubKey": buildScriptPubKeyJson(output.scriptPubKey, mainnet, regtest)
  }

proc sighashToStr*(sighashType: int32): string =
  ## Map a PSBT sighash-type integer to its Bitcoin Core string label.
  ##
  ## Reference: bitcoin-core/src/core_io.cpp SighashToStr (line ~343).
  ## The map covers the 6 defined SIGHASH values; anything else returns "".
  ##
  ## PSBT_IN_SIGHASH_TYPE stores a 4-byte little-endian uint32; the lower byte
  ## is the sighash flag (the same byte that is appended to a DER signature).
  let low = uint8(sighashType and 0xff)
  case low
  of 0x01: "ALL"
  of 0x02: "NONE"
  of 0x03: "SINGLE"
  of 0x81: "ALL|ANYONECANPAY"
  of 0x82: "NONE|ANYONECANPAY"
  of 0x83: "SINGLE|ANYONECANPAY"
  else: ""

proc isValidDerSigEncoding*(vch: seq[byte]): bool =
  ## Check whether a push looks like a valid DER signature (+ sighash byte).
  ##
  ## Mirrors bitcoin-core/src/script/interpreter.cpp IsValidSignatureEncoding.
  ## Used by `disassembleScriptSigAsmStr` to decide whether to append [SigHashType].
  if vch.len < 9 or vch.len > 73: return false
  if vch[0] != 0x30: return false
  if vch[1] != uint8(vch.len - 3): return false
  let lenR = int(vch[3])
  if 5 + lenR >= vch.len: return false
  let lenS = int(vch[5 + lenR])
  if lenR + lenS + 7 != vch.len: return false
  if vch[2] != 0x02: return false
  if lenR == 0: return false
  if (vch[4] and 0x80) != 0: return false
  if lenR > 1 and vch[4] == 0x00 and (vch[5] and 0x80) == 0: return false
  if vch[lenR + 4] != 0x02: return false
  if lenS == 0: return false
  if (vch[lenR + 6] and 0x80) != 0: return false
  if lenS > 1 and vch[lenR + 6] == 0x00 and (vch[lenR + 7] and 0x80) == 0: return false
  true

proc disassembleScriptSigAsmStr*(script: seq[byte]): string =
  ## Disassemble a scriptSig with sighash-type decoding enabled.
  ##
  ## Reference: bitcoin-core/src/core_io.cpp ScriptToAsmStr(..., fAttemptSighashDecode=true).
  ##
  ## For push-data operands whose length > 4:
  ##   1. Check IsValidSignatureEncoding (DER format + sighash byte).
  ##   2. If it passes, strip the last byte, map it via sighashToStr, and
  ##      append the "[TYPE]" suffix if the type is defined.
  ##   3. Emit hex(stripped_data) + optional "[TYPE]" suffix.
  ## For push-data operands whose length <= 4: emit as CScriptNum decimal.
  ## Non-push opcodes: same as disassembleScript.
  var result = ""
  var i = 0

  proc pushDataHex(data: seq[byte]): string =
    var h = ""
    for b in data:
      h.add(toHex(b, 2).toLowerAscii())
    h

  while i < script.len:
    if result.len > 0:
      result.add(" ")

    let op = script[i]

    # Push data opcodes
    var dataLen = 0
    var dataStart = 0
    if op >= 0x01 and op <= 0x4b:
      dataLen = int(op)
      dataStart = i + 1
      i += 1 + dataLen
    elif op == 0x4c:  # OP_PUSHDATA1
      if i + 1 >= script.len: result.add("[error]"); break
      dataLen = int(script[i + 1])
      dataStart = i + 2
      i += 2 + dataLen
    elif op == 0x4d:  # OP_PUSHDATA2
      if i + 2 >= script.len: result.add("[error]"); break
      dataLen = int(script[i + 1]) or (int(script[i + 2]) shl 8)
      dataStart = i + 3
      i += 3 + dataLen
    elif op == 0x4e:  # OP_PUSHDATA4
      if i + 4 >= script.len: result.add("[error]"); break
      dataLen = int(script[i + 1]) or (int(script[i + 2]) shl 8) or
                (int(script[i + 3]) shl 16) or (int(script[i + 4]) shl 24)
      dataStart = i + 5
      i += 5 + dataLen
    else:
      # Non-push opcode — same table as disassembleScript
      let opName = case op
        of 0x00: "0"
        of 0x4f: "-1"
        of 0x51: "1"
        of 0x52: "2"
        of 0x53: "3"
        of 0x54: "4"
        of 0x55: "5"
        of 0x56: "6"
        of 0x57: "7"
        of 0x58: "8"
        of 0x59: "9"
        of 0x5a: "10"
        of 0x5b: "11"
        of 0x5c: "12"
        of 0x5d: "13"
        of 0x5e: "14"
        of 0x5f: "15"
        of 0x60: "16"
        else:
          # Re-use the opcode names from disassembleScript's else branch
          case op
          of 0x61: "OP_NOP"
          of 0x63: "OP_IF"
          of 0x64: "OP_NOTIF"
          of 0x67: "OP_ELSE"
          of 0x68: "OP_ENDIF"
          of 0x69: "OP_VERIFY"
          of 0x6a: "OP_RETURN"
          of 0x6b: "OP_TOALTSTACK"
          of 0x6c: "OP_FROMALTSTACK"
          of 0x6d: "OP_2DROP"
          of 0x6e: "OP_2DUP"
          of 0x6f: "OP_3DUP"
          of 0x70: "OP_2OVER"
          of 0x71: "OP_2ROT"
          of 0x72: "OP_2SWAP"
          of 0x73: "OP_IFDUP"
          of 0x74: "OP_DEPTH"
          of 0x75: "OP_DROP"
          of 0x76: "OP_DUP"
          of 0x77: "OP_NIP"
          of 0x78: "OP_OVER"
          of 0x79: "OP_PICK"
          of 0x7a: "OP_ROLL"
          of 0x7b: "OP_ROT"
          of 0x7c: "OP_SWAP"
          of 0x7d: "OP_TUCK"
          of 0x82: "OP_SIZE"
          of 0x87: "OP_EQUAL"
          of 0x88: "OP_EQUALVERIFY"
          of 0x8b: "OP_1ADD"
          of 0x8c: "OP_1SUB"
          of 0x8f: "OP_NEGATE"
          of 0x90: "OP_ABS"
          of 0x91: "OP_NOT"
          of 0x92: "OP_0NOTEQUAL"
          of 0x93: "OP_ADD"
          of 0x94: "OP_SUB"
          of 0x9a: "OP_BOOLAND"
          of 0x9b: "OP_BOOLOR"
          of 0x9c: "OP_NUMEQUAL"
          of 0x9d: "OP_NUMEQUALVERIFY"
          of 0x9e: "OP_NUMNOTEQUAL"
          of 0x9f: "OP_LESSTHAN"
          of 0xa0: "OP_GREATERTHAN"
          of 0xa1: "OP_LESSTHANOREQUAL"
          of 0xa2: "OP_GREATERTHANOREQUAL"
          of 0xa3: "OP_MIN"
          of 0xa4: "OP_MAX"
          of 0xa5: "OP_WITHIN"
          of 0xa6: "OP_RIPEMD160"
          of 0xa7: "OP_SHA1"
          of 0xa8: "OP_SHA256"
          of 0xa9: "OP_HASH160"
          of 0xaa: "OP_HASH256"
          of 0xab: "OP_CODESEPARATOR"
          of 0xac: "OP_CHECKSIG"
          of 0xad: "OP_CHECKSIGVERIFY"
          of 0xae: "OP_CHECKMULTISIG"
          of 0xaf: "OP_CHECKMULTISIGVERIFY"
          of 0xb0: "OP_NOP1"
          of 0xb1: "OP_CHECKLOCKTIMEVERIFY"
          of 0xb2: "OP_CHECKSEQUENCEVERIFY"
          of 0xb3: "OP_NOP4"
          of 0xb4: "OP_NOP5"
          of 0xb5: "OP_NOP6"
          of 0xb6: "OP_NOP7"
          of 0xb7: "OP_NOP8"
          of 0xb8: "OP_NOP9"
          of 0xb9: "OP_NOP10"
          of 0xba: "OP_CHECKSIGADD"
          else: "OP_UNKNOWN[" & toHex(op, 2) & "]"
      result.add(opName)
      i += 1
      continue

    # We have a push: dataStart..dataStart+dataLen
    if dataStart + dataLen > script.len:
      result.add("[error]")
      break

    let vch = script[dataStart ..< dataStart + dataLen]
    if vch.len <= 4:
      # CScriptNum decimal
      var v: int64 = 0
      if vch.len > 0:
        for j in 0 ..< vch.len:
          v = v or (int64(vch[j]) shl (8 * j))
        if (vch[vch.len - 1] and 0x80) != 0:
          let mask = int64(0x80) shl (8 * (vch.len - 1))
          v = -(v and not mask)
      result.add($v)
    else:
      # Attempt sighash decode
      var decoded = vch
      var sighashSuffix = ""
      if isValidDerSigEncoding(vch):
        let shType = sighashToStr(int32(vch[^1]))
        if shType.len > 0:
          decoded = vch[0 ..< vch.len - 1]
          sighashSuffix = "[" & shType & "]"
      result.add(pushDataHex(decoded) & sighashSuffix)

  result

proc buildScriptTypeJson*(script: seq[byte]): JsonNode =
  ## Build script JSON object with {asm, hex, type} — no desc, no address.
  ##
  ## Used for redeem_script / witness_script fields in decodepsbt input objects.
  ## Reference: bitcoin-core/src/core_io.cpp ScriptToUniv called with default
  ## args (include_address=false), which means NO `desc` and NO `address` are
  ## emitted — only asm + hex + type.
  let scriptType = getScriptType(script)
  %*{
    "asm": disassembleScript(script),
    "hex": toHex(script),
    "type": scriptType
  }

proc buildNonWitnessUtxoJson*(prevTx: Transaction, mainnet: bool): JsonNode =
  ## Build the full TxToUniv shape for non_witness_utxo, WITHOUT the "hex" field.
  ##
  ## Reference: bitcoin-core/src/rpc/rawtransaction.cpp line 1142:
  ##   TxToUniv(*input.non_witness_utxo, uint256(), non_wit, /*include_hex=*/false)
  ##
  ## Shape: {txid, hash, version, size, vsize, weight, locktime, vin[], vout[]}
  ## vin[i]: {txid, vout, scriptSig:{asm,hex}, sequence, txinwitness?}
  ##         (or {coinbase, sequence} for coinbase inputs)
  ## vout[i]: {value, n, scriptPubKey:{asm,desc,hex,address?,type}}
  ##
  ## Note: "hash" is the wtxid (witness tx hash), not the txid.
  ## Note: "size" is the serialized size INCLUDING witness; same as Core's
  ##       ComputeTotalSize().
  let txid = prevTx.txid()
  let wtxid = prevTx.wtxid()
  let weight = validation.calculateTransactionWeight(prevTx)
  let vsize = (weight + 3) div 4
  let size = serialize(prevTx).len

  result = newJObject()
  result["txid"] = %reverseHex(toHex(array[32, byte](txid)))
  result["hash"] = %reverseHex(toHex(array[32, byte](wtxid)))
  result["version"] = %prevTx.version
  result["size"] = %size
  result["vsize"] = %vsize
  result["weight"] = %weight
  result["locktime"] = %prevTx.lockTime

  # vin array
  var vinArr = newJArray()
  for idx, inp in prevTx.inputs:
    let isCoinbase = inp.prevOut.txid == TxId(default(array[32, byte])) and
                     inp.prevOut.vout == 0xFFFFFFFF'u32
    var vinObj = newJObject()
    if isCoinbase:
      vinObj["coinbase"] = %toHex(inp.scriptSig)
    else:
      vinObj["txid"] = %reverseHex(toHex(array[32, byte](inp.prevOut.txid)))
      vinObj["vout"] = %inp.prevOut.vout
      vinObj["scriptSig"] = %*{
        "asm": disassembleScriptSigAsmStr(inp.scriptSig),
        "hex": toHex(inp.scriptSig)
      }
    # txinwitness — only when non-empty
    if idx < prevTx.witnesses.len and prevTx.witnesses[idx].len > 0:
      var witnessArr = newJArray()
      for item in prevTx.witnesses[idx]:
        witnessArr.add(%toHex(item))
      vinObj["txinwitness"] = witnessArr
    vinObj["sequence"] = %inp.sequence
    vinArr.add(vinObj)
  result["vin"] = vinArr

  # vout array (full scriptPubKey shape with desc + address)
  var voutArr = newJArray()
  for idx, outp in prevTx.outputs:
    voutArr.add(buildVoutJson(outp, idx, mainnet))
  result["vout"] = voutArr

proc buildVerboseTxJson(tx: Transaction, blockHash: Option[BlockHash],
                        confirmations: int32, blocktime: uint32,
                        inActiveChain: Option[bool], mainnet: bool,
                        regtest: bool = false): JsonNode =
  ## Build complete verbose transaction JSON.
  ## `regtest` selects the "bcrt" bech32 HRP for vout scriptPubKey addresses.
  let txid = tx.txid()
  let wtxid = tx.wtxid()
  let weight = validation.calculateTransactionWeight(tx)
  let vsize = (weight + 3) div 4

  result = %*{
    "txid": reverseHex(toHex(array[32, byte](txid))),
    "hash": reverseHex(toHex(array[32, byte](wtxid))),
    "version": tx.version,
    "size": serialize(tx).len,
    "vsize": vsize,
    "weight": weight,
    "locktime": tx.lockTime
  }

  # Add vin array
  var vinArray = newJArray()
  for i in 0 ..< tx.inputs.len:
    vinArray.add(buildVinJson(tx, i))
  result["vin"] = vinArray

  # Add vout array
  var voutArray = newJArray()
  for i, outp in tx.outputs:
    voutArray.add(buildVoutJson(outp, i, mainnet, regtest))
  result["vout"] = voutArray

  # Add hex
  result["hex"] = %toHex(serialize(tx))

  # Add block info if confirmed
  if blockHash.isSome:
    result["blockhash"] = %reverseHex(toHex(array[32, byte](blockHash.get())))
    result["confirmations"] = %confirmations
    result["time"] = %blocktime
    result["blocktime"] = %blocktime

  # Add in_active_chain if blockhash was explicitly provided
  if inActiveChain.isSome:
    result["in_active_chain"] = %inActiveChain.get()

proc enrichVerbosity2(rpc: RpcServer, tx: Transaction, result: var JsonNode,
                      mainnet: bool,
                      currentBlockIdx: Option[BlockIndex],
                      txInBlockIdx: int,
                      regtest: bool = false) =
  ## Add verbosity=2 fields to a getrawtransaction response:
  ##   - per-vin "prevout" enrichment {generated, height, value, scriptPubKey}
  ##   - top-level "fee" (sum inputs - sum outputs, in BTC)
  ##
  ## Prevout resolution strategy (priority order):
  ##   1. txindex → creating block → creating tx outputs + height + coinbase flag
  ##   2. Flat file BlockUndo (current block undo data) — per (txIdx, inputIdx)
  ##   3. RocksDB UndoData outpoint map
  ##
  ## Reference: bitcoin-core/src/core_io.cpp TxToUniv (have_undo path) and
  ## bitcoin-core/src/rpc/rawtransaction.cpp getrawtransaction verbosity==2.

  # Phase 1: txindex batch lookup — group inputs by creating block, read once.
  # Maps inp.prevOut → (value_sats, scriptPubKey_bytes, height, isCoinbase).
  type PrevoutInfo = tuple[value: int64, script: seq[byte], height: int32, generated: bool]
  var prevoutMap: Table[OutPoint, PrevoutInfo]
  var resolvedTxids: HashSet[TxId]

  # Check if tx is coinbase (skip prevout enrichment for coinbase inputs).
  let isTxCoinbase = tx.inputs.len > 0 and
    tx.inputs[0].prevOut.txid == TxId(default(array[32, byte])) and
    tx.inputs[0].prevOut.vout == 0xFFFFFFFF'u32

  if not isTxCoinbase:
    # Group inputs by creating block hash for amortized block reads.
    type TxRef = tuple[spendTxId: TxId, txIndex: int]
    var blockNeeds: Table[BlockHash, seq[TxRef]]

    for inp in tx.inputs:
      if inp.prevOut.txid in resolvedTxids: continue
      let locOpt = rpc.chainState.db.getTxIndex(inp.prevOut.txid)
      if locOpt.isSome:
        let loc = locOpt.get()
        if loc.blockHash notin blockNeeds:
          blockNeeds[loc.blockHash] = @[]
        blockNeeds[loc.blockHash].add((inp.prevOut.txid, int(loc.txIndex)))
        resolvedTxids.incl(inp.prevOut.txid)

    # For each creating block, read once and extract all needed outputs.
    for creatingBlockHash, refs in blockNeeds:
      let creatingBlkOpt = rpc.chainState.db.getBlock(creatingBlockHash)
      if creatingBlkOpt.isNone: continue
      let creatingBlk = creatingBlkOpt.get()

      # Get creating block's height for the height field.
      let creatingIdxOpt = rpc.chainState.db.getBlockIndex(creatingBlockHash)
      let creatingHeight = if creatingIdxOpt.isSome: creatingIdxOpt.get().height else: 0'i32

      for r in refs:
        if r.txIndex >= creatingBlk.txs.len: continue
        let creatingTx = creatingBlk.txs[r.txIndex]
        # Determine if this creating tx is coinbase.
        let creatingIsCoinbase = creatingTx.inputs.len > 0 and
          creatingTx.inputs[0].prevOut.txid == TxId(default(array[32, byte])) and
          creatingTx.inputs[0].prevOut.vout == 0xFFFFFFFF'u32

        # Populate ALL outputs of this creating tx.
        for voutIdx, creatingOut in creatingTx.outputs:
          let op = OutPoint(txid: r.spendTxId, vout: uint32(voutIdx))
          prevoutMap[op] = (int64(creatingOut.value), creatingOut.scriptPubKey,
                            creatingHeight, creatingIsCoinbase)

    # Phase 2: flat file BlockUndo fallback for inputs not in txindex.
    var blockUndoLoaded: Option[BlockUndo]
    if currentBlockIdx.isSome:
      let blkIdx = currentBlockIdx.get()
      let buOpt = rpc.chainState.getBlockUndoFromFile(blkIdx, blkIdx.prevHash)
      if buOpt.isSome:
        blockUndoLoaded = buOpt

    # Phase 3: RocksDB UndoData fallback.
    var undoDataLoaded: Option[UndoData]
    if currentBlockIdx.isSome:
      let udOpt = rpc.chainState.db.getUndoData(currentBlockIdx.get().hash)
      if udOpt.isSome:
        undoDataLoaded = udOpt

    # Build prevout JSON for each vin using resolved data.
    var amtIn: int64 = 0
    var amtOut: int64 = 0
    var allInputsKnown = true

    let vinNode = result["vin"]
    for inpIdx, inp in tx.inputs:
      var info: PrevoutInfo
      var found = false

      # 1. Check txindex-resolved map.
      if inp.prevOut in prevoutMap:
        info = prevoutMap[inp.prevOut]
        found = true

      # 2. Flat file BlockUndo (current block undo, per txIdx-1, inpIdx).
      if not found and blockUndoLoaded.isSome:
        let bu = blockUndoLoaded.get()
        let txUndoIdx = txInBlockIdx - 1  # undo is 0-indexed for non-coinbase txs
        if txUndoIdx >= 0 and txUndoIdx < bu.txUndo.len:
          let txUndo = bu.txUndo[txUndoIdx]
          if inpIdx < txUndo.prevOutputs.len:
            let spent = txUndo.prevOutputs[inpIdx]
            info = (int64(spent.output.value), spent.output.scriptPubKey,
                    spent.height, spent.isCoinbase)
            found = true

      # 3. RocksDB UndoData outpoint map.
      if not found and undoDataLoaded.isSome:
        for (op, entry) in undoDataLoaded.get().spentOutputs:
          if op == inp.prevOut:
            info = (int64(entry.output.value), entry.output.scriptPubKey,
                    entry.height, entry.isCoinbase)
            found = true
            break

      if found:
        amtIn += info.value
        var prevoutObj = newJObject()
        prevoutObj["generated"] = %info.generated
        prevoutObj["height"] = %info.height
        prevoutObj["value"] = btcAmountNode(info.value)
        prevoutObj["scriptPubKey"] = buildScriptPubKeyJson(info.script, mainnet, regtest)
        vinNode[inpIdx]["prevout"] = prevoutObj
      else:
        allInputsKnown = false

    for outp in tx.outputs:
      amtOut += int64(outp.value)

    # Add top-level fee if all inputs resolved and fee is non-negative.
    let fee = amtIn - amtOut
    if allInputsKnown and fee >= 0:
      result["fee"] = btcAmountNode(fee)

proc handleGetRawTransaction(rpc: RpcServer, params: JsonNode): JsonNode =
  ## getrawtransaction "txid" ( verbose "blockhash" )
  ##
  ## Returns raw transaction data.
  ##   verbose=0 (or false, default) → hex string
  ##   verbose=1 (or true)           → JSON object with decoded transaction data
  ##   verbose=2                     → verbose + per-vin prevout enrichment + fee
  ##
  ## By default, only mempool transactions are returned. With txindex enabled,
  ## confirmed transactions can also be retrieved. If blockhash is provided,
  ## the transaction is searched for only in that specific block.
  ##
  ## Reference: Bitcoin Core /src/rpc/rawtransaction.cpp getrawtransaction

  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing txid parameter")

  let txidHex = params[0].getStr()
  # Core ParseHashV: a malformed txid (wrong length or non-hex) is
  # RPC_INVALID_PARAMETER (-8) at the parse boundary, before any lookup.
  validateHashV(txidHex, "parameter 1")

  # Parse verbosity parameter (int or bool).
  #   false / 0  → raw hex
  #   true  / 1  → verbose JSON (TxToUniv, no prevout)
  #   2          → verbose JSON + per-vin prevout + fee (W60)
  var verbosity = 0
  if params.len >= 2:
    if params[1].kind == JBool:
      verbosity = if params[1].getBool(): 1 else: 0
    elif params[1].kind == JInt:
      verbosity = params[1].getInt()
    elif params[1].kind == JNull:
      discard  # Keep default 0
    else:
      raise newRpcError(RpcInvalidParams, "verbose must be a boolean or integer")

  let txid = parseTxId(txidHex)

  # Special exception for the genesis block coinbase transaction. Its txid is,
  # by construction, equal to the genesis block's merkle root. Core refuses to
  # serve it (rpc/rawtransaction.cpp:290-293), raising RPC_INVALID_ADDRESS_OR_KEY.
  let genesisMerkleRoot = buildGenesisBlock(rpc.params).header.merkleRoot
  if array[32, byte](txid) == genesisMerkleRoot:
    raise newRpcError(RpcInvalidAddressOrKey,
      "The genesis block coinbase is not considered an ordinary transaction and cannot be retrieved")

  # Parse optional blockhash parameter
  var explicitBlockHash: Option[BlockHash] = none(BlockHash)
  if params.len >= 3 and params[2].kind == JString:
    let blockHashHex = params[2].getStr()
    # Core ParseHashV (rawtransaction.cpp:300, name "parameter 3"): malformed
    # blockhash is RPC_INVALID_PARAMETER (-8) at the parse boundary.
    validateHashV(blockHashHex, "parameter 3")
    explicitBlockHash = some(parseBlockHash(blockHashHex))

  let mainnet = rpc.params.network == Mainnet
  let regtest = rpc.params.network == Regtest

  # If blockhash is explicitly provided, search only in that block
  if explicitBlockHash.isSome:
    let blockHash = explicitBlockHash.get()

    # Check if block exists
    let blkOpt = rpc.chainState.db.getBlock(blockHash)
    if blkOpt.isNone:
      raise newRpcError(RpcInvalidAddressOrKey, "Block hash not found")

    let blk = blkOpt.get()

    # Check if block has data (not pruned)
    let idxOpt = rpc.chainState.db.getBlockIndex(blockHash)
    if idxOpt.isNone:
      raise newRpcError(RpcMiscError, "Block not available")

    # Search for transaction in block; track index for undo-data fallback.
    var foundTx: Option[Transaction] = none(Transaction)
    var txInBlockIdx = 0
    for i, tx in blk.txs:
      if tx.txid() == txid:
        foundTx = some(tx)
        txInBlockIdx = i
        break

    if foundTx.isNone:
      raise newRpcError(RpcInvalidAddressOrKey,
        "No such transaction found in the provided block. Use gettransaction for wallet transactions.")

    let tx = foundTx.get()

    if verbosity == 0:
      return %toHex(serialize(tx))

    # Check if block is in active chain
    let blockIdx = idxOpt.get()
    let heightHashOpt = rpc.chainState.db.getBlockHashByHeight(blockIdx.height)
    let inActiveChain = heightHashOpt.isSome and heightHashOpt.get() == blockHash

    let confirmations = if inActiveChain:
      rpc.chainState.bestHeight - blockIdx.height + 1
    else:
      -1'i32  # Not in active chain

    var txJson = buildVerboseTxJson(tx, some(blockHash), confirmations,
                                    blk.header.timestamp, some(inActiveChain),
                                    mainnet, regtest)

    if verbosity >= 2:
      enrichVerbosity2(rpc, tx, txJson, mainnet, some(blockIdx), txInBlockIdx, regtest)

    return txJson

  # No explicit blockhash: check mempool first, then txindex
  let mempoolTx = rpc.mempool.getTransaction(txid)
  if mempoolTx.isSome:
    let tx = mempoolTx.get()

    if verbosity == 0:
      return %toHex(serialize(tx))

    # Unconfirmed transaction — no block info, no undo data.
    # verbosity=2 cannot resolve prevouts for mempool txs; emit verbosity=1 shape.
    return buildVerboseTxJson(tx, none(BlockHash), 0, 0, none(bool), mainnet, regtest)

  # Check tx index for confirmed transactions
  let locOpt = rpc.chainState.db.getTxIndex(txid)
  if locOpt.isNone:
    raise newRpcError(RpcInvalidAddressOrKey,
      "No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries. Use gettransaction for wallet transactions.")

  let loc = locOpt.get()
  let blkOpt = rpc.chainState.db.getBlock(loc.blockHash)
  if blkOpt.isNone:
    raise newRpcError(RpcInternalError, "Block not found for indexed transaction")

  let blk = blkOpt.get()
  if int(loc.txIndex) >= blk.txs.len:
    raise newRpcError(RpcInternalError, "Invalid transaction index")

  let tx = blk.txs[loc.txIndex]

  if verbosity == 0:
    return %toHex(serialize(tx))

  let idxOpt = rpc.chainState.db.getBlockIndex(loc.blockHash)
  let blockHeight = if idxOpt.isSome: idxOpt.get().height else: 0'i32
  let confirmations = rpc.chainState.bestHeight - blockHeight + 1

  var txJson = buildVerboseTxJson(tx, some(loc.blockHash), confirmations,
                                  blk.header.timestamp, none(bool), mainnet, regtest)

  if verbosity >= 2:
    let blockIdxForUndo = idxOpt
    enrichVerbosity2(rpc, tx, txJson, mainnet, blockIdxForUndo, int(loc.txIndex), regtest)

  txJson

proc handleDecodeRawTransaction(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Decode a raw transaction hex to a TxToUniv-shaped JSON object.
  ##
  ## Reference: bitcoin-core/src/rpc/rawtransaction.cpp decoderawtransaction()
  ## → TxToUniv(tx, block_hash=uint256(), entry, include_hex=false)
  ## → core_io.cpp TxToUniv (vin via ScriptToAsmStr(fAttemptSighashDecode=true),
  ##   vout via ScriptPubKeyToUniv with include_address=true).
  ##
  ## Shape: {txid, hash, version, size, vsize, weight, locktime, vin[], vout[]}.
  ## No top-level "hex" field (Core's include_hex=false at rawtransaction.cpp:443).
  ##
  ## Uses the same buildVinJson / buildVoutJson helpers as decodepsbt so that
  ## vin (coinbase detection, txinwitness, scriptSig.asm) and vout
  ## (btcAmountNode 8-decimal, buildScriptPubKeyJson with desc/type/address)
  ## are byte-identical with Bitcoin Core 31.99 (W55).
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing hexstring parameter")

  let txHex = params[0].getStr()
  let mainnet = rpc.params.network == Mainnet
  let regtest = rpc.params.network == Regtest

  try:
    let txBytes = hexToBytes(txHex)
    let tx = deserializeTransaction(txBytes)
    let txid = tx.txid()
    let wtxid = tx.wtxid()
    let weight = validation.calculateTransactionWeight(tx)

    var inputs = newJArray()
    for i in 0 ..< tx.inputs.len:
      inputs.add(buildVinJson(tx, i))

    var outputs = newJArray()
    for i, outp in tx.outputs:
      outputs.add(buildVoutJson(outp, i, mainnet, regtest))

    %*{
      "txid": reverseHex(toHex(array[32, byte](txid))),
      "hash": reverseHex(toHex(array[32, byte](wtxid))),
      "version": tx.version,
      "size": txBytes.len,
      "vsize": (weight + 3) div 4,
      "weight": weight,
      "locktime": tx.lockTime,
      "vin": inputs,
      "vout": outputs
    }
  except CatchableError as e:
    raise newRpcError(RpcInvalidParams, "invalid transaction: " & e.msg)

proc uvTypeName(node: JsonNode): string =
  ## Mirror of Bitcoin Core's univalue ``UniValue::typeName`` (univalue.cpp:34),
  ## used to render the dispatcher type-error messages byte-for-byte. Core maps
  ## VOBJ->"object", VARR->"array", VSTR->"string", VNUM->"number",
  ## VBOOL->"bool", VNULL->"null".
  case node.kind
  of JObject: "object"
  of JArray:  "array"
  of JString: "string"
  of JInt:    "number"
  of JFloat:  "number"
  of JBool:   "bool"
  of JNull:   "null"

proc handleCombineRawTransaction(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Combine multiple partially-signed versions of the SAME transaction into one
  ## carrying the union of their signature data.
  ##
  ## Reference: bitcoin-core/src/rpc/rawtransaction.cpp combinerawtransaction
  ## (impl body 605-668). Each element of ``txs`` is a hex-encoded raw tx with
  ## the SAME inputs/outputs/version/locktime but DIFFERENT partial signatures.
  ## The first variant is the structural template; per input we merge the
  ## scriptSig + witness across all variants and write the combined result back.
  ## Returns the witness-serialized hex.
  ##
  ## SCOPE (= the ouroboros f4c98ee reference): single-sig parity, the dominant
  ## case. For an input where each variant carries a complete single-key
  ## signature for a DIFFERENT subset of inputs (or a variant is unsigned), we
  ## take, per input, the non-empty (signed) scriptSig + witness. This is
  ## BYTE-IDENTICAL to Core for single-sig inputs (P2PKH / P2WPKH / P2SH-P2WPKH),
  ## because Core's ``DataFromTransaction`` returns the variant's scriptSig +
  ## scriptWitness verbatim once ``VerifyScript`` marks the input complete, and
  ## ``MergeSignatureData`` adopts that complete sigdata wholesale.
  ##
  ## KNOWN LIMITATION (flagged, NOT faked): the FULL Core behavior also merges
  ## PARTIAL multisig signatures WITHIN a single input (two variants each
  ## holding one of M sigs for a bare/P2SH/P2WSH M-of-N) via the extracted
  ## (pubkey -> sig) map. That needs Solver / VerifyScript-with-a-signature-
  ## extracting-checker / sighash validation, which this handler does NOT
  ## implement. For an input partially signed in BOTH variants (neither alone
  ## complete) we keep the longer (more-signatures) scriptSig+witness rather
  ## than splicing the two sig sets together; that input's output is therefore
  ## NOT guaranteed byte-identical to Core. The single-sig pick IS byte-identical.
  ##
  ## DEVIATION (flagged): Core resolves every input's prevout from its own
  ## UTXO + mempool ``CCoinsViewCache`` and throws RPC_VERIFY_ERROR (-25)
  ## "Input not found or already spent" when a coin is missing/spent. This
  ## handler does NOT consult chainstate — combine is a pure function of the
  ## provided variants here — so it does NOT raise -25 for unresolvable
  ## prevouts. The byte-identical SUCCESS vector must therefore be run against a
  ## Core oracle whose UTXO actually resolves the prevouts (a scratch regtest).
  ## The -22 empty / -22 decode-failure / -3 type error paths DO match Core.

  # Param shape: Core renders ``txs`` via the RPCHelpMan named-arg validator,
  # so a non-array surfaces as RPC_TYPE_ERROR (-3) with the "Wrong type passed"
  # wrapper (verified against live Core 8332). Missing arg behaves the same.
  if params.len < 1 or params[0].kind != JArray:
    let got =
      if params.len < 1: "null"
      else: uvTypeName(params[0])
    raise newRpcError(RpcTypeError,
      "Wrong type passed:\n{\n    \"Position 1 (txs)\": " &
      "\"JSON value of type " & got &
      " is not of expected type array\"\n}")

  let txsArr = params[0]

  # 1. Decode every variant (witness-aware). Core: DecodeHexTx per idx; on
  #    failure -> -22 "TX decode failed for tx %d. ..." (0-based idx).
  #    Iterate by INDEX (a 2-var `for` over a JsonNode binds pairs() which
  #    asserts JObject and raises a non-catchable Defect on a JArray).
  var variants: seq[Transaction]
  for idx in 0 ..< txsArr.len:
    let item = txsArr[idx]
    if item.kind != JString:
      # Core reads each element with .get_str() -> type error.
      raise newRpcError(RpcTypeError,
        "JSON value of type " & uvTypeName(item) &
        " is not of expected type string")
    var decoded: Transaction
    var ok = true
    try:
      let raw = hexToBytes(item.getStr())
      decoded = deserializeTransaction(raw)
      if decoded.inputs.len == 0:
        ok = false
    except CatchableError:
      ok = false
    if not ok:
      raise newRpcError(RpcDeserializationError,
        "TX decode failed for tx " & $idx &
        ". Make sure the tx has at least one input.")
    variants.add(decoded)

  # 2. Empty array -> -22 "Missing transactions".
  if variants.len == 0:
    raise newRpcError(RpcDeserializationError, "Missing transactions")

  # 3. mergedTx starts as a clone of the first variant (the template: its
  #    version / locktime / vin / vout define the result; only each input's
  #    scriptSig + witness get rebuilt below).
  let templateTx = variants[0]

  var mergedInputs: seq[TxIn]
  var mergedWitnesses: seq[seq[seq[byte]]]
  var anyWitness = false

  for i in 0 ..< templateTx.inputs.len:
    let base = templateTx.inputs[i]
    var bestScriptSig: seq[byte] = @[]
    var bestWitness: seq[seq[byte]] = @[]
    var bestScore = -1  # rank candidates; higher = more complete

    for v in 0 ..< variants.len:
      let variant = variants[v]
      if i >= variant.inputs.len:
        continue
      let ss = variant.inputs[i].scriptSig
      var wit: seq[seq[byte]] = @[]
      if i < variant.witnesses.len:
        wit = variant.witnesses[i]
      var witNonEmpty = false
      var witLen = 0
      for x in wit:
        witLen += x.len
        if x.len > 0:
          witNonEmpty = true
      let ssNonEmpty = ss.len > 0

      # Score the candidate so we deterministically prefer the variant that
      # actually carries signature data for this input. Tie-break by total
      # signature-data length (longer = more sigs, matching the partial-
      # multisig fallback note above). Equal length -> keep the earliest
      # variant (Core's merge is order-stable for the complete single-sig case).
      var score: int
      if not ssNonEmpty and not witNonEmpty:
        score = 0
      else:
        score = 1_000_000 + ss.len + witLen

      if score > bestScore:
        bestScore = score
        bestScriptSig = ss
        bestWitness = wit

    var bestWitNonEmpty = false
    for x in bestWitness:
      if x.len > 0:
        bestWitNonEmpty = true
        break
    if bestWitNonEmpty:
      anyWitness = true

    mergedInputs.add(TxIn(
      prevOut: base.prevOut,
      scriptSig: bestScriptSig,
      sequence: base.sequence,
    ))
    mergedWitnesses.add(bestWitness)

  # Core re-encodes WITH witness (TX_WITH_WITNESS) unconditionally; nimrod's
  # writeTransaction only emits the segwit marker/flag when tx.witnesses has a
  # non-empty stack, so mirror Core (whose CTransaction::HasWitness drives the
  # marker): keep the per-input witnesses iff ANY input carries one, otherwise
  # clear them so the serializer emits a legacy (non-segwit) encoding.
  var merged = Transaction(
    version: templateTx.version,
    inputs: mergedInputs,
    outputs: templateTx.outputs,
    lockTime: templateTx.lockTime,
  )
  if anyWitness:
    merged.witnesses = mergedWitnesses

  %toHex(merged.serialize(includeWitness = true))

proc buildP2SHWrapAddress(script: seq[byte], mainnet: bool,
                          regtest: bool = false): string =
  ## Compute P2SH-wrap address for a redeem script.
  ## P2SH = base58check(version=0x05/0xC4 || HASH160(redeemScript))
  ## P2SH base58 prefixes are identical on testnet and regtest, so `regtest`
  ## is accepted for signature symmetry but does not change the result.
  let h = hash160(script)
  let addrVal = Address(kind: P2SH, scriptHash: h)
  encodeAddress(addrVal, mainnet, regtest)

proc buildP2WPKHScript(hash: openArray[byte]): seq[byte] =
  ## Build OP_0 <20-byte-hash> witness program (P2WPKH).
  result = newSeq[byte](22)
  result[0] = 0x00  # OP_0
  result[1] = 0x14  # push 20 bytes
  for i in 0 ..< 20:
    result[2 + i] = hash[i]

proc buildP2WSHScript(script: seq[byte]): seq[byte] =
  ## Build OP_0 <32-byte-SHA256(script)> witness program (P2WSH).
  let h = sha256(script)
  result = newSeq[byte](34)
  result[0] = 0x00  # OP_0
  result[1] = 0x20  # push 32 bytes
  for i in 0 ..< 32:
    result[2 + i] = h[i]

proc extractPubkeyFromP2PK(script: seq[byte]): seq[byte] =
  ## Extract the raw pubkey bytes from a P2PK script: <pushLen> <pubkey> OP_CHECKSIG.
  if script.len < 35:
    return @[]
  let pushLen = int(script[0])
  if (pushLen == 33 or pushLen == 65) and script.len == pushLen + 2:
    return script[1 ..< 1 + pushLen]
  return @[]

proc extractPubkeysFromMultisig(script: seq[byte]): seq[seq[byte]] =
  ## Extract pubkeys from a multisig script: OP_M <pubkeys> OP_N OP_CHECKMULTISIG.
  ## Returns empty list if parsing fails.
  result = @[]
  if script.len < 4 or script[^1] != 0xae:
    return
  var i = 1  # skip OP_M
  while i < script.len - 2:  # stop before OP_N OP_CHECKMULTISIG
    let pushLen = int(script[i])
    if pushLen == 0:
      break
    if i + 1 + pushLen > script.len:
      return @[]
    result.add(script[i + 1 ..< i + 1 + pushLen])
    i += 1 + pushLen

proc allPubkeysCompressed(pubkeys: seq[seq[byte]]): bool =
  ## Check that all pubkeys are compressed (33 bytes, prefix 0x02 or 0x03).
  for pk in pubkeys:
    if pk.len != 33:
      return false
    if pk[0] != 0x02 and pk[0] != 0x03:
      return false
  return true

proc hasOpChecksigAdd(script: seq[byte]): bool =
  ## Check if script contains OP_CHECKSIGADD (0xba).
  for b in script:
    if b == 0xba:  # OP_CHECKSIGADD
      return true
  return false

proc handleDecodeScript(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Decode a hex-encoded script.
  ##
  ## Reference: bitcoin-core/src/rpc/rawtransaction.cpp `decodescript` (~line 450)
  ##
  ## Shape: {asm, desc, type, address?, p2sh?, segwit?}
  ## Key: top-level has NO `hex` field (ScriptToUniv called with include_hex=false).
  ## Inner segwit object HAS `hex` (ScriptToUniv called with include_hex=true).
  ##
  ## can_wrap types: pubkey, pubkeyhash, multisig, nonstandard,
  ##   witness_v0_keyhash, witness_v0_scripthash.
  ## can_wrap_P2WSH types: pubkey (compressed only), pubkeyhash, nonstandard,
  ##   multisig (compressed only).
  ##
  ## Segwit wrap construction:
  ##   PUBKEY    → P2WPKH(Hash160(pubkey))
  ##   PUBKEYHASH → P2WPKH(raw-hash-in-script)
  ##   Others    → P2WSH(SHA256(script))
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing hexstring parameter")

  let hexStr = params[0].getStr()
  let script: seq[byte] =
    if hexStr.len > 0:
      try:
        hexToBytes(hexStr)
      except CatchableError as e:
        raise newRpcError(RpcInvalidParams, "script decode failed: " & e.msg)
    else:
      @[]

  let mainnet = rpc.params.network == Mainnet
  let regtest = rpc.params.network == Regtest
  let scriptType = getScriptType(script)

  # Build top-level object (same as buildScriptPubKeyJson but WITHOUT hex).
  # Core decodescript / ScriptToUniv key order: asm, desc, address, type.
  let addrOpt = extractAddressFromScript(script, mainnet, regtest)
  result = %*{
    "asm": disassembleScript(script),
    "desc": inferAddrDescriptor(script, mainnet, regtest)
  }
  if addrOpt.isSome:
    result["address"] = %addrOpt.get()
  result["type"] = %scriptType

  # Determine can_wrap (mirrors Core's switch + validity checks).
  let canWrap =
    case scriptType
    of "pubkey", "pubkeyhash", "multisig", "nonstandard",
       "witness_v0_keyhash", "witness_v0_scripthash":
      # Additional checks: not unspendable (OP_RETURN prefix), no OP_CHECKSIGADD
      let isUnspendable = script.len > 0 and script[0] == 0x6a  # OP_RETURN
      not isUnspendable and not hasOpChecksigAdd(script)
    else:
      # nulldata, scripthash, witness_v1_taproot, anchor, witness_unknown
      false

  if canWrap:
    result["p2sh"] = %buildP2SHWrapAddress(script, mainnet, regtest)

    # Determine can_wrap_P2WSH.
    let canWrapP2WSH =
      case scriptType
      of "pubkey":
        let pk = extractPubkeyFromP2PK(script)
        pk.len == 33  # only compressed pubkeys (33 bytes, not 65)
      of "multisig":
        let pks = extractPubkeysFromMultisig(script)
        allPubkeysCompressed(pks)
      of "pubkeyhash", "nonstandard":
        true
      else:
        # witness_v0_keyhash, witness_v0_scripthash → already segwit, no P2WSH wrap
        false

    if canWrapP2WSH:
      # Build the witness script and its ScriptToUniv-shaped inner object.
      let segwitScript: seq[byte] =
        case scriptType
        of "pubkey":
          # P2WPKH from Hash160(pubkey)
          let pk = extractPubkeyFromP2PK(script)
          buildP2WPKHScript(hash160(pk))
        of "pubkeyhash":
          # P2WPKH from raw 20-byte hash in script (bytes 3..22)
          buildP2WPKHScript(script[3 ..< 23])
        else:
          # P2WSH from SHA256(script) for nonstandard/multisig
          buildP2WSHScript(script)

      # Inner segwit object uses ScriptToUniv key order: asm, desc, hex,
      # address, type, then p2sh-segwit.
      let segwitAddrOpt = extractAddressFromScript(segwitScript, mainnet, regtest)
      var sr = %*{
        "asm": disassembleScript(segwitScript),
        "desc": inferAddrDescriptor(segwitScript, mainnet, regtest),
        "hex": toHex(segwitScript)
      }
      if segwitAddrOpt.isSome:
        sr["address"] = %segwitAddrOpt.get()
      sr["type"] = %getScriptType(segwitScript)
      # p2sh-segwit = P2SH wrap of the witness script
      sr["p2sh-segwit"] = %buildP2SHWrapAddress(segwitScript, mainnet, regtest)

      result["segwit"] = sr

proc isFullyValidPubkeyBytes(pkBytes: seq[byte]): bool =
  ## Returns true if pkBytes is a cryptographically valid EC public key.
  ## Compressed (33 bytes, 0x02/0x03) or uncompressed (65 bytes, 0x04).
  ## Mirrors Bitcoin Core CPubKey::IsFullyValid() (pubkey.h).
  if pkBytes.len == 33:
    if pkBytes[0] != 0x02 and pkBytes[0] != 0x03:
      return false
    # Use decompressPubkey as a secp256k1 parse proxy: returns @[] on invalid.
    let decompressed = decompressPubkey(pkBytes)
    return decompressed.len == 65
  elif pkBytes.len == 65:
    if pkBytes[0] != 0x04:
      return false
    # Structural check only for uncompressed (no secp256k1 on-curve check here).
    # Core's IsFullyValid also calls secp256k1_ec_pubkey_parse; we accept
    # well-formed uncompressed keys as valid (invalid points rejected by script eval).
    return true
  else:
    return false

proc buildMultisigRedeemScript(nRequired: int, pubkeys: seq[seq[byte]]): seq[byte] =
  ## Build OP_M <push><pk1> ... <push><pkN> OP_N OP_CHECKMULTISIG.
  ## OP_M = 0x50 + nRequired, OP_N = 0x50 + len(pubkeys).
  result = @[byte(0x50 + nRequired)]
  for pk in pubkeys:
    let pushLen = byte(pk.len)  # 0x21 for 33-byte, 0x41 for 65-byte
    result.add(pushLen)
    result.add(pk)
  result.add(byte(0x50 + pubkeys.len))
  result.add(0xae'u8)  # OP_CHECKMULTISIG

proc handleCreateMultisig(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Create a multisig address from nrequired and a list of public keys.
  ##
  ## Reference: Bitcoin Core rpc/output_script.cpp createmultisig (~line 89)
  ##
  ## Params:
  ## [0] nrequired  - Number of signatures required (int, 1..16)
  ## [1] keys       - Array of hex-encoded public key strings
  ## [2] address_type - Optional: "legacy" (default), "bech32", "p2sh-segwit"
  ##
  ## Returns {address, redeemScript, descriptor, warnings?}
  if params.len < 2:
    raise newRpcError(RpcInvalidParams, "createmultisig requires nrequired and keys parameters")

  # Parse nrequired
  let nRequired =
    if params[0].kind == JInt:
      int(params[0].getInt())
    else:
      raise newRpcError(RpcInvalidParams, "nrequired must be an integer")

  # Parse keys array
  if params[1].kind != JArray:
    raise newRpcError(RpcInvalidParams, "keys must be an array")
  let keysNode = params[1]

  # Validate nrequired bounds before key count
  if nRequired < 1:
    raise newRpcError(RpcInvalidParams,
      "a multisignature address must require at least one key to redeem")

  # Parse and validate each pubkey
  var pubkeys: seq[seq[byte]]
  for i in 0 ..< keysNode.len:
    let hexStr = keysNode[i].getStr()
    if hexStr.len != 66 and hexStr.len != 130:
      raise newRpcError(RpcInvalidAddressOrKey,
        "Pubkey \"" & hexStr & "\" must have a length of either 33 or 65 bytes")
    let pkBytes =
      try: hexToBytes(hexStr)
      except CatchableError:
        raise newRpcError(RpcInvalidAddressOrKey,
          "Pubkey \"" & hexStr & "\" must be a hex string")
    if not isFullyValidPubkeyBytes(pkBytes):
      raise newRpcError(RpcInvalidAddressOrKey,
        "Pubkey \"" & hexStr & "\" must be cryptographically valid.")
    pubkeys.add(pkBytes)

  let nKeys = pubkeys.len
  if nKeys < nRequired:
    raise newRpcError(RpcInvalidParams,
      "not enough keys supplied (got " & $nKeys & " keys, but need at least " & $nRequired & " to redeem)")
  if nKeys > 16:
    raise newRpcError(RpcInvalidParams,
      "Number of keys involved in the multisignature address creation > 16\nReduce the number")

  # Parse address_type (default "legacy")
  let addrType =
    if params.len >= 3 and params[2].kind == JString:
      params[2].getStr()
    else:
      "legacy"

  if addrType notin ["legacy", "bech32", "p2sh-segwit"]:
    raise newRpcError(RpcInvalidAddressOrKey,
      "Unknown address type '" & addrType & "'")
  if addrType == "bech32m":
    raise newRpcError(RpcInvalidAddressOrKey,
      "createmultisig cannot create bech32m multisig addresses")

  # Check if any key is uncompressed — Core forces legacy in that case
  var hasUncompressed = false
  for pk in pubkeys:
    if pk.len == 65:
      hasUncompressed = true
      break
  var effectiveType = addrType
  var warnings: seq[string] = @[]
  if hasUncompressed and effectiveType != "legacy":
    effectiveType = "legacy"
    warnings.add("Unable to make chosen address type, please ensure no uncompressed public keys are present.")

  let mainnet = rpc.params.network == Mainnet

  # Build redeemScript = OP_M <pk1> ... <pkN> OP_N OP_CHECKMULTISIG
  let redeemScript = buildMultisigRedeemScript(nRequired, pubkeys)
  let redeemScriptHex = toHex(redeemScript)

  # Derive address and descriptor based on effective type
  let (address, descriptor) =
    case effectiveType
    of "legacy":
      # P2SH: HASH160(redeemScript)
      let h = hash160(redeemScript)
      let addrVal = Address(kind: P2SH, scriptHash: h)
      let addrStr = encodeAddress(addrVal, mainnet)
      # Descriptor: sh(multi(M,pk1,...))#csum
      var pkHexes: seq[string]
      for pk in pubkeys:
        pkHexes.add(toHex(pk))
      let descInner = "sh(multi(" & $nRequired & "," & pkHexes.join(",") & "))"
      let descStr = addDescriptorChecksum(descInner)
      (addrStr, descStr)
    of "bech32":
      # P2WSH: SHA256(redeemScript) as v0 witness program
      let h = sha256(redeemScript)
      var wsh: array[32, byte]
      for i in 0 ..< 32: wsh[i] = h[i]
      let addrVal = Address(kind: P2WSH, wsh: wsh)
      let addrStr = encodeAddress(addrVal, mainnet)
      # Descriptor: wsh(multi(M,pk1,...))#csum
      var pkHexes: seq[string]
      for pk in pubkeys:
        pkHexes.add(toHex(pk))
      let descInner = "wsh(multi(" & $nRequired & "," & pkHexes.join(",") & "))"
      let descStr = addDescriptorChecksum(descInner)
      (addrStr, descStr)
    of "p2sh-segwit":
      # P2SH(P2WSH): HASH160 of the P2WSH script (0x00 0x20 <sha256>)
      let p2wshScript = buildP2WSHScript(redeemScript)
      let h = hash160(p2wshScript)
      let addrVal = Address(kind: P2SH, scriptHash: h)
      let addrStr = encodeAddress(addrVal, mainnet)
      # Descriptor: sh(wsh(multi(M,pk1,...)))#csum
      var pkHexes: seq[string]
      for pk in pubkeys:
        pkHexes.add(toHex(pk))
      let descInner = "sh(wsh(multi(" & $nRequired & "," & pkHexes.join(",") & ")))"
      let descStr = addDescriptorChecksum(descInner)
      (addrStr, descStr)
    else:
      raise newRpcError(RpcInvalidAddressOrKey, "Unknown address type: " & effectiveType)

  result = %*{
    "address": address,
    "redeemScript": redeemScriptHex,
    "descriptor": descriptor
  }
  if warnings.len > 0:
    result["warnings"] = %warnings

proc handleSendRawTransaction(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Submit a raw transaction to the network
  ## Reference: Bitcoin Core sendrawtransaction RPC
  ##
  ## Params:
  ## [0] hexstring - The hex-encoded raw transaction
  ## [1] maxfeerate - (optional) Maximum fee rate in BTC/kvB (default 0.10)
  ##
  ## Returns: txid as hex string
  ## Errors:
  ## - RPC_TRANSACTION_REJECTED (-26): Mempool rejected the tx
  ## - RPC_TRANSACTION_ALREADY_IN_CHAIN (-27): Tx already confirmed
  ## - RPC_TRANSACTION_ERROR (-25): Generic tx error (missing inputs, etc.)
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing hexstring parameter")

  let txHex = params[0].getStr()

  # Parse maxfeerate parameter (BTC/kvB, default 0.10)
  var maxFeeRate = DefaultMaxFeeRate  # 0.10 BTC/kvB
  if params.len >= 2:
    if params[1].kind == JFloat:
      maxFeeRate = params[1].getFloat()
    elif params[1].kind == JInt:
      maxFeeRate = float64(params[1].getInt())
    elif params[1].kind == JString:
      try:
        maxFeeRate = parseFloat(params[1].getStr())
      except ValueError:
        raise newRpcError(RpcInvalidParams, "invalid maxfeerate")

  # Reject fee rates > 1 BTC/kvB (sanity check per Bitcoin Core)
  if maxFeeRate > 1.0:
    raise newRpcError(RpcInvalidParams, "maxfeerate cannot exceed 1 BTC/kvB")

  try:
    let txBytes = hexToBytes(txHex)
    let tx = deserializeTransaction(txBytes)
    let txid = tx.txid()
    let txidHex = reverseHex(toHex(array[32, byte](txid)))

    # Check if transaction is already in chain
    # If any output of this transaction exists in the UTXO set, it's confirmed
    let utxo = rpc.chainState.getUtxo(OutPoint(txid: txid, vout: 0))
    if utxo.isSome:
      raise newRpcError(RpcTransactionAlreadyInChain, "transaction already in block chain")

    # Also check tx index if available
    let locOpt = rpc.chainState.db.getTxIndex(txid)
    if locOpt.isSome:
      raise newRpcError(RpcTransactionAlreadyInChain, "transaction already in block chain")

    # Check if already in mempool - this is idempotent, return txid without error
    if rpc.mempool.contains(txid):
      # Already in mempool, just return the txid (idempotent)
      # Re-broadcast to peers to help propagation
      if rpc.peerManager != nil:
        asyncSpawn rpc.peerManager.broadcastTx(tx)
      return %txidHex

    # Calculate transaction weight and fee rate
    let weight = validation.calculateTransactionWeight(tx)
    let vsize = (weight + 3) div 4  # Round up

    # Add to mempool (validates the transaction)
    var mp = rpc.mempool
    let acceptResult = mp.acceptTransaction(tx, rpc.crypto)

    if not acceptResult.isOk:
      let errMsg = acceptResult.error
      # Map error messages to appropriate error codes
      if errMsg.contains("input not found") or errMsg.contains("missing"):
        raise newRpcError(RpcTransactionError, "missing inputs: " & errMsg)
      elif errMsg.contains("double spend"):
        raise newRpcError(RpcTransactionRejected, errMsg)
      else:
        raise newRpcError(RpcTransactionRejected, errMsg)

    # Get the fee from mempool entry to check maxfeerate
    let entry = rpc.mempool.get(txid)
    if entry.isSome:
      let fee = int64(entry.get().fee)
      # Convert maxfeerate from BTC/kvB to sat/vB
      # 0.10 BTC/kvB = 0.10 * 100,000,000 / 1000 = 10,000 sat/vB
      let maxFeeRateSatPerVb = maxFeeRate * 100_000_000.0 / 1000.0
      let actualFeeRate = float64(fee) / float64(vsize)

      if maxFeeRate > 0 and actualFeeRate > maxFeeRateSatPerVb:
        # Remove from mempool - fee too high
        mp.removeTransaction(txid)
        let feeRateBtcKvb = actualFeeRate * 1000.0 / 100_000_000.0
        raise newRpcError(RpcTransactionRejected,
          "fee rate " & $feeRateBtcKvb & " BTC/kvB exceeds maxfeerate " & $maxFeeRate & " BTC/kvB")

    # Broadcast inv to peers (let them request the full tx)
    if rpc.peerManager != nil:
      asyncSpawn rpc.peerManager.broadcastTx(tx)

    %txidHex
  except RpcError:
    raise
  except CatchableError as e:
    raise newRpcError(RpcInvalidParams, "TX decode failed: " & e.msg)

proc handleTestMempoolAccept(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Dry-run mempool acceptance check for one or more raw transactions.
  ## Reference: Bitcoin Core testmempoolaccept RPC (rpc/mempool.cpp)
  ##
  ## Params:
  ## [0] rawtxs   - Array of hex-encoded raw transactions (1..25)
  ## [1] maxfeerate - (optional) Maximum fee rate in BTC/kvB (default 0.10)
  ##
  ## Returns: JSON array with one entry per transaction:
  ##   { "txid": hex, "wtxid": hex,
  ##     "allowed": true, "vsize": N,
  ##       "fees": { "base": BTC, "effective-feerate": sat/vB,
  ##                 "effective-includes": [wtxid, ...] }
  ##   }
  ##   or on rejection:
  ##   { "txid": hex, "wtxid": hex, "allowed": false, "reject-reason": str }
  ##
  ## Single tx  → acceptTransactionWithArgs(testAccept=true)  (no mutation)
  ## Multi tx   → acceptPackage(usePackageFeerates=true) then rollback
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing rawtxs array parameter")
  if params[0].kind != JArray:
    raise newRpcError(RpcInvalidParams, "rawtxs must be an array of hex strings")

  let rawTxsArray = params[0]
  if rawTxsArray.len == 0:
    raise newRpcError(RpcInvalidParams, "rawtxs array must not be empty")
  if rawTxsArray.len > MaxPackageCount:
    raise newRpcError(RpcInvalidParams,
      "too many transactions in package: " & $rawTxsArray.len &
      " > " & $MaxPackageCount)

  # Parse maxfeerate (BTC/kvB, default 0.10; 0 = unlimited)
  var maxFeeRate = DefaultMaxFeeRate
  if params.len >= 2 and params[1].kind != JNull:
    if params[1].kind == JFloat:
      maxFeeRate = params[1].getFloat()
    elif params[1].kind == JInt:
      maxFeeRate = float64(params[1].getInt())
    elif params[1].kind == JString:
      try:
        maxFeeRate = parseFloat(params[1].getStr())
      except ValueError:
        raise newRpcError(RpcInvalidParams, "invalid maxfeerate")
  if maxFeeRate > 1.0:
    raise newRpcError(RpcInvalidParams, "maxfeerate cannot exceed 1 BTC/kvB")

  # Decode all transactions.
  #
  # NB: iterate the JArray by INDEX, never `for i, x in rawTxsArray`. The
  # 2-variable `for` over a JsonNode binds std/json's `pairs(JsonNode)`
  # iterator, which asserts `node.kind == JObject` and raises an
  # AssertionDefect on a JArray. That Defect is NOT a CatchableError, so it
  # escaped every handler here and surfaced to the client as a bogus
  # "-32700 parse error" with id:null — making testmempoolaccept [[hex]]
  # (the Core-shaped nested-array call) unreachable. Indexing avoids pairs().
  var txns: seq[Transaction]
  for i in 0 ..< rawTxsArray.len:
    let rawTxNode = rawTxsArray[i]
    if rawTxNode.kind != JString:
      raise newRpcError(RpcInvalidParams,
        "rawtxs[" & $i & "] must be a hex string")
    let txHex = rawTxNode.getStr()
    try:
      let txBytes = hexToBytes(txHex)
      let tx = deserializeTransaction(txBytes)
      txns.add(tx)
    except CatchableError as e:
      raise newRpcError(RpcInvalidParams,
        "TX " & $i & " decode failed: " & e.msg)

  var resultArr = newJArray()

  if txns.len == 1:
    # ── Single-tx path ──────────────────────────────────────────────────────
    # Use testAccept=true so no mempool mutation occurs.
    let tx = txns[0]
    let txid    = tx.txid()
    let wtxid   = tx.wtxid()
    let txidHex  = reverseHex(toHex(array[32, byte](txid)))
    let wtxidHex = reverseHex(toHex(array[32, byte](wtxid)))

    # Core CHECK_NONFATAL: already-in-mempool txns are not "allowed" for
    # testmempoolaccept (rpc/mempool.cpp:370).
    if rpc.mempool.contains(txid):
      var entry = %*{
        "txid": txidHex,
        "wtxid": wtxidHex,
        "allowed": false,
        "reject-reason": "txn-already-in-mempool"
      }
      resultArr.add(entry)
      return resultArr

    var mp = rpc.mempool
    let args = AtmpArgs(
      testAccept: true,
      bypassLimits: false,
      allowReplacement: true,
      allowSiblingEviction: false,
      packageFeerates: false,
      clientMaxFeeRateSatKvB: 0.0
    )
    let res = mp.acceptTransactionWithArgs(tx, rpc.crypto, args)

    var txEntry = %*{ "txid": txidHex, "wtxid": wtxidHex }

    if res.isOk:
      let info = res.value
      let vsize = info.vsize
      let feeBtc = float64(int64(info.baseFee)) / 100_000_000.0
      let feeSatPerVb = if vsize > 0: float64(int64(info.baseFee)) / float64(vsize)
                        else: 0.0

      # maxfeerate check (per-tx, before any state commit — testAccept=true
      # guarantees nothing was mutated above)
      if maxFeeRate > 0:
        let maxFeeRateSatPerVb = maxFeeRate * 100_000_000.0 / 1000.0
        if feeSatPerVb > maxFeeRateSatPerVb:
          txEntry["allowed"] = %false
          txEntry["reject-reason"] = %("max-fee-exceeded")
          resultArr.add(txEntry)
          return resultArr

      txEntry["allowed"] = %true
      txEntry["vsize"] = %vsize
      txEntry["fees"] = %*{
        "base": feeBtc,
        "effective-feerate": feeSatPerVb,
        "effective-includes": %*[wtxidHex]
      }
    else:
      txEntry["allowed"] = %false
      txEntry["reject-reason"] = %res.error

    resultArr.add(txEntry)

  else:
    # ── Multi-tx (package) path ─────────────────────────────────────────────
    # Run full package validation (usePackageFeerates=true for CPFP), then
    # roll back all newly-added entries so the mempool is not mutated.
    var mp = rpc.mempool

    # Record which txids are in the mempool before we call acceptPackage so we
    # can remove anything that was freshly inserted.
    var preExisting: seq[TxId]
    for tx in txns:
      if mp.contains(tx.txid()):
        preExisting.add(tx.txid())

    let pkgResult = mp.acceptPackage(txns, rpc.crypto, usePackageFeerates = true)

    # Rollback: remove every tx that acceptPackage added (was not pre-existing).
    for tx in txns:
      let txid = tx.txid()
      var wasPreExisting = false
      for pe in preExisting:
        if pe == txid:
          wasPreExisting = true
          break
      if not wasPreExisting and mp.contains(txid):
        mp.removeTransaction(txid)

    # Build per-tx results
    let maxFeeRateSatPerVb = if maxFeeRate > 0:
                               maxFeeRate * 100_000_000.0 / 1000.0
                             else: 0.0

    # If the package-level validation failed before we got per-tx results,
    # mark all txs as rejected with the package error.
    if pkgResult.txResults.len == 0:
      for tx in txns:
        let txid    = tx.txid()
        let wtxid   = tx.wtxid()
        let txidHex  = reverseHex(toHex(array[32, byte](txid)))
        let wtxidHex = reverseHex(toHex(array[32, byte](wtxid)))
        resultArr.add(%*{
          "txid": txidHex,
          "wtxid": wtxidHex,
          "allowed": false,
          "reject-reason": pkgResult.error
        })
      return resultArr

    for txResult in pkgResult.txResults:
      let txidHex  = reverseHex(toHex(array[32, byte](txResult.txid)))
      let wtxidHex = reverseHex(toHex(array[32, byte](txResult.wtxid)))

      var txEntry = %*{ "txid": txidHex, "wtxid": wtxidHex }

      # Core: already-in-mempool is not "allowed" for testmempoolaccept
      var rejectedAlreadyInMempool = false
      for pe in preExisting:
        if pe == txResult.txid:
          rejectedAlreadyInMempool = true
          break

      if rejectedAlreadyInMempool:
        txEntry["allowed"] = %false
        txEntry["reject-reason"] = %"txn-already-in-mempool"
      elif txResult.allowed:
        let vsize = txResult.vsize
        let feeBtc = float64(int64(txResult.fees)) / 100_000_000.0
        let feeSatPerVb = if vsize > 0: float64(int64(txResult.fees)) / float64(vsize)
                          else: 0.0

        if maxFeeRate > 0 and feeSatPerVb > maxFeeRateSatPerVb:
          txEntry["allowed"] = %false
          txEntry["reject-reason"] = %"max-fee-exceeded"
        else:
          txEntry["allowed"] = %true
          txEntry["vsize"] = %vsize
          txEntry["fees"] = %*{
            "base": feeBtc,
            "effective-feerate": pkgResult.packageFeerate,
            "effective-includes": newJArray()
          }
      else:
        txEntry["allowed"] = %false
        txEntry["reject-reason"] = %txResult.error

      resultArr.add(txEntry)

  resultArr

proc handleSubmitPackage(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Submit a package of raw transactions to the network (CPFP support)
  ## Reference: Bitcoin Core submitpackage RPC
  ##
  ## Params:
  ## [0] rawtxs - Array of hex-encoded raw transactions (topologically sorted)
  ## [1] maxfeerate - (optional) Maximum fee rate in BTC/kvB (default 0.10)
  ## [2] maxburnamount - (optional) Maximum burned amount in BTC (default 0)
  ##
  ## Returns: Object with package acceptance results
  ##
  ## Note: Package must be topologically sorted (parents before children)
  ## The child transaction's fee can pay for its parent's inclusion (CPFP)
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing rawtxs array parameter")

  if params[0].kind != JArray:
    raise newRpcError(RpcInvalidParams, "rawtxs must be an array of hex strings")

  let rawTxsArray = params[0]

  if rawTxsArray.len == 0:
    raise newRpcError(RpcInvalidParams, "rawtxs array must not be empty")

  if rawTxsArray.len > MaxPackageCount:
    raise newRpcError(RpcInvalidParams, "package too many transactions: " &
                     $rawTxsArray.len & " > " & $MaxPackageCount)

  # Parse maxfeerate parameter (BTC/kvB, default 0.10)
  var maxFeeRate = DefaultMaxFeeRate  # 0.10 BTC/kvB
  if params.len >= 2 and params[1].kind != JNull:
    if params[1].kind == JFloat:
      maxFeeRate = params[1].getFloat()
    elif params[1].kind == JInt:
      maxFeeRate = float64(params[1].getInt())
    elif params[1].kind == JString:
      try:
        maxFeeRate = parseFloat(params[1].getStr())
      except ValueError:
        raise newRpcError(RpcInvalidParams, "invalid maxfeerate")

  if maxFeeRate > 1.0:
    raise newRpcError(RpcInvalidParams, "maxfeerate cannot exceed 1 BTC/kvB")

  # Parse all transactions.
  #
  # NB: iterate the JArray by INDEX (see handleTestMempoolAccept) — the 2-var
  # `for i, x in rawTxsArray` binds std/json's `pairs(JsonNode)` iterator which
  # asserts JObject and raises an (uncatchable) AssertionDefect on a JArray.
  var txns: seq[Transaction]
  for i in 0 ..< rawTxsArray.len:
    let rawTxNode = rawTxsArray[i]
    if rawTxNode.kind != JString:
      raise newRpcError(RpcInvalidParams, "rawtxs[" & $i & "] must be a hex string")

    let txHex = rawTxNode.getStr()
    try:
      let txBytes = hexToBytes(txHex)
      let tx = deserializeTransaction(txBytes)
      txns.add(tx)
    except CatchableError as e:
      raise newRpcError(RpcInvalidParams, "TX " & $i & " decode failed: " & e.msg)

  # Enforce child-with-parents-tree topology before submitting.
  # Reference: Bitcoin Core rpc/mempool.cpp:1395
  #   if (txns.size() > 1 && !IsChildWithParentsTree(txns))
  #     throw JSONRPCTransactionError(TransactionError::INVALID_PACKAGE,
  #       "package topology disallowed. not child-with-parents or parents depend on each other.")
  if txns.len > 1 and not isChildWithParentsTree(txns):
    raise newRpcError(RpcTransactionRejected,
      "package topology disallowed. not child-with-parents or parents depend on each other.")

  # Validate and submit package
  var mp = rpc.mempool
  let pkgResult = mp.acceptPackage(txns, rpc.crypto, usePackageFeerates = true)

  # Build tx_results object
  var txResults = newJObject()
  for i, txResult in pkgResult.txResults:
    let txidHex = reverseHex(toHex(array[32, byte](txResult.txid)))
    let wtxidHex = reverseHex(toHex(array[32, byte](txResult.wtxid)))

    var txResultObj = %*{
      "txid": txidHex,
      "wtxid": wtxidHex,
      "vsize": txResult.vsize
    }

    if txResult.allowed:
      # Calculate fee in BTC
      let feeBtc = float64(int64(txResult.fees)) / 100_000_000.0
      txResultObj["allowed"] = %true
      txResultObj["fees"] = %*{
        "base": feeBtc
      }
    else:
      txResultObj["allowed"] = %false
      txResultObj["reject-reason"] = %txResult.error

    txResults[wtxidHex] = txResultObj

  # Build response
  var response = %*{
    "package_msg": (if pkgResult.valid: "success" else: pkgResult.error),
    "tx-results": txResults
  }

  # Add replaced transactions info (empty for now, would need RBF tracking)
  response["replaced-transactions"] = newJArray()

  # If package was accepted, check maxfeerate
  if pkgResult.valid:
    # Convert maxfeerate from BTC/kvB to sat/vB
    let maxFeeRateSatPerVb = maxFeeRate * 100_000_000.0 / 1000.0

    if maxFeeRate > 0 and pkgResult.packageFeerate > maxFeeRateSatPerVb:
      # Package fee rate exceeds maximum
      let feeRateBtcKvb = pkgResult.packageFeerate * 1000.0 / 100_000_000.0
      raise newRpcError(RpcTransactionRejected,
        "package fee rate " & $feeRateBtcKvb & " BTC/kvB exceeds maxfeerate " & $maxFeeRate & " BTC/kvB")

    # Broadcast all transactions
    if rpc.peerManager != nil:
      for tx in txns:
        asyncSpawn rpc.peerManager.broadcastTx(tx)

  response

# ZMQ RPCs
proc handleGetZmqNotifications(rpc: RpcServer): JsonNode =
  ## Return information about the active ZMQ notification publishers
  ## Reference: Bitcoin Core rpc/misc.cpp getzmqnotifications
  var notifications = newJArray()

  if rpc.zmq != nil:
    for notifier in rpc.zmq.getActiveNotifiers():
      notifications.add(%*{
        "type": notifier.notifierType,
        "address": notifier.address,
        "hwm": notifier.hwm
      })

  notifications

# Network RPCs
proc handlePing(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Requests that a ping be sent to all connected peers, to measure ping time.
  ## Reference: Bitcoin Core rpc/net.cpp ping (:84-107) ->
  ## PeerManager::SendPings (net_processing.cpp:2237).
  ##
  ## Params: none. Core takes {} and any argument is a dispatcher arity error.
  ##
  ## Behaviour: side-effect-only control method. Iterates every connected peer
  ## and fires a BIP-31 P2P PING (fire-and-forget) via the same `sendPingsNow`
  ## primitive the keepalive loop uses. It does NOT measure latency synchronously
  ## or wait for the PONGs — the round-trip results surface LATER via
  ## getpeerinfo's `pingtime` / `minping` fields. With zero peers it is a
  ## successful no-op. Returns JSON null immediately (Core UniValue::VNULL).
  ##
  ## No method-specific arg validation: Core's ping takes no params and relies on
  ## the dispatcher's arity check; extra params are ignored here (the dispatcher
  ## already accepts/normalizes params before this handler runs).

  # EnsurePeerman parity: a missing peer manager is P2P-disabled, code -31
  # (Core RPC_CLIENT_P2P_DISABLED), NOT an empty success.
  if rpc.peerManager == nil:
    raise newRpcError(RpcClientP2pDisabled,
      "Error: Peer-to-peer functionality missing or disabled")

  # Fire-and-forget: queue/emit a PING to every ready peer and return immediately.
  # Core only requests the ping (sets m_ping_queued) and returns; it does not
  # block on the responses. asyncSpawn mirrors that non-blocking fan-out — a
  # per-peer send error is swallowed inside sendPings and can never fail the RPC
  # (peerless / dropped peers tolerated). On a peerless node this spawns a
  # no-op loop over an empty peer set and still returns null.
  asyncSpawn rpc.peerManager.sendPingsNow()

  # Core returns UniValue::VNULL -> JSON null.
  newJNull()

proc handleSetNetworkActive(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Disable/enable all p2p network activity.
  ## Reference: Bitcoin Core rpc/net.cpp setnetworkactive (:889) +
  ## CConnman::SetNetworkActive (net.cpp:3361).
  ##
  ## Param:
  ##   state (bool, REQUIRED): true to enable networking, false to disable.
  ##
  ## Returns the value that was passed in (a bare JSON boolean), read back from
  ## the peer manager after the toggle (Core returns GetNetworkActive(), which
  ## absent a race equals `state`). Setting false suppresses NEW connection
  ## establishment ONLY — existing peers are NOT disconnected. The `networkactive`
  ## field of getnetworkinfo mirrors this flag.

  # Required positional bool. Core reads request.params[0].get_bool(): a missing
  # arg is RPC_INVALID_PARAMETER (-8); a non-bool (int/float/string) is a JSON
  # type error (RPC_TYPE_ERROR, -3). get_bool() is strict — it does NOT coerce
  # ints/floats, so we accept only JBool.
  if params.len < 1 or params[0].kind == JNull:
    raise newRpcError(RpcInvalidParameter, "Missing required argument: state")
  if params[0].kind != JBool:
    raise newRpcError(RpcTypeError,
      "JSON value of type " & $params[0].kind & " is not of expected type bool")
  let state = params[0].getBool()

  # EnsureConnman parity (server_util.cpp): a missing peer manager is
  # RPC_CLIENT_P2P_DISABLED (-31), NOT an empty success.
  if rpc.peerManager == nil:
    raise newRpcError(RpcClientP2pDisabled,
      "Error: Peer-to-peer functionality missing or disabled")

  # SetNetworkActive then return the read-back value (Core net.cpp:904-906).
  newJBool(rpc.peerManager.setNetworkActive(state))

proc handleGetNetworkInfo(rpc: RpcServer): JsonNode =
  ## Return information about P2P networking
  ## Reference: Bitcoin Core rpc/net.cpp getnetworkinfo
  let connCount = if rpc.peerManager != nil: rpc.peerManager.connectedPeerCount() else: 0
  let inCount = if rpc.peerManager != nil: rpc.peerManager.inboundCount() else: 0
  let outCount = if rpc.peerManager != nil: rpc.peerManager.outboundCount() else: 0

  # Build networks array.
  # BUG-5 FIX (W117): i2p and cjdns entries were missing. Core reports all 5
  # network types (ipv4/ipv6/onion/i2p/cjdns) in getnetworkinfo.
  # Reference: bitcoin-core/src/rpc/net.cpp GetNetworksInfo()
  let networks = %*[
    {
      "name": "ipv4",
      "limited": false,
      "reachable": true,
      "proxy": "",
      "proxy_randomize_credentials": false
    },
    {
      "name": "ipv6",
      "limited": false,
      "reachable": true,
      "proxy": "",
      "proxy_randomize_credentials": false
    },
    {
      "name": "onion",
      "limited": true,
      "reachable": false,
      "proxy": "",
      "proxy_randomize_credentials": false
    },
    {
      "name": "i2p",
      "limited": true,
      "reachable": false,
      "proxy": "",
      "proxy_randomize_credentials": false
    },
    {
      "name": "cjdns",
      "limited": true,
      "reachable": false,
      "proxy": "",
      "proxy_randomize_credentials": false
    }
  ]

  # localservices MUST reflect the REAL service word we advertise on the wire,
  # not a re-derivation. `advertisedServices()` (peer.nim) is the SAME accessor
  # `sendVersion` feeds into the outbound `version` message, so the RPC view can
  # never drift from what peers actually see. Default = NODE_NETWORK |
  # NODE_WITNESS | NODE_NETWORK_LIMITED | NODE_P2P_V2 = 0xc09 (NETWORK_LIMITED is
  # unconditional per BIP-159; P2P_V2 because the inbound v2 responder is
  # default-on; +COMPACT_FILTERS when advertiseCompactFiltersService()). It also
  # tracks future flag toggles automatically — do NOT re-hardcode the word here.
  let localServicesBits: uint64 = advertisedServices()
  # Derive the names array from the SAME word so hex + names can never diverge.
  # Bit-walk low->high in Core's protocol.cpp serviceFlagToStr order so the
  # localservicesnames array byte-matches Core for any given service word.
  var localServicesNames = newJArray()
  if (localServicesBits and NodeNetwork) != 0:         localServicesNames.add(%"NETWORK")
  if (localServicesBits and NodeBloom) != 0:           localServicesNames.add(%"BLOOM")
  if (localServicesBits and NodeWitness) != 0:         localServicesNames.add(%"WITNESS")
  if (localServicesBits and NodeCompactFilters) != 0:  localServicesNames.add(%"COMPACT_FILTERS")
  if (localServicesBits and NodeNetworkLimited) != 0:  localServicesNames.add(%"NETWORK_LIMITED")
  if (localServicesBits and NodeP2pV2) != 0:           localServicesNames.add(%"P2P_V2")
  let localServicesHex = toHex(localServicesBits, 16).toLowerAscii()

  # networkactive mirrors the node-global P2P-active flag (Core
  # CConnman::GetNetworkActive, surfaced at rpc/net.cpp getnetworkinfo). Toggled
  # by setnetworkactive; defaults true. Falls back to true when no peer manager
  # is wired (test rigs) so the field shape is unchanged.
  let networkActive =
    if rpc.peerManager != nil: rpc.peerManager.networkActiveState() else: true

  %*{
    "version": 210000,
    "subversion": "/nimrod:0.1.0/",
    "protocolversion": 70016,
    "localservices": localServicesHex,
    "localservicesnames": localServicesNames,
    "localrelay": true,
    "timeoffset": 0,
    "networkactive": networkActive,
    "connections": connCount,
    "connections_in": inCount,
    "connections_out": outCount,
    "networks": networks,
    # Core: relayfee = minRelayTxFee.GetFeePerK(), incrementalfee =
    # incrementalRelayFee.GetFeePerK(); both default to 100 sat/kvB =
    # 0.00000100 BTC. Coupled to the live mempool floor (mp.minFeeRate, sat/vB)
    # and mp.incrementalRelayFeeRate (sat/kvB) — NOT hardcoded — so they track
    # the real admission floor. Emit via btcAmountNode for Core's 8-decimal text.
    "relayfee": btcAmountNode(int64(rpc.mempool.minFeeRate * 1000.0 + 0.5)),
    "incrementalfee": btcAmountNode(int64(rpc.mempool.incrementalRelayFeeRate + 0.5)),
    "localaddresses": [],
    # Core v31.99 emits warnings as an array of strings (empty = no warnings).
    "warnings": newJArray()
  }

proc handleGetPeerInfo(rpc: RpcServer): JsonNode =
  ## Return data about each connected network peer
  ## Reference: Bitcoin Core rpc/net.cpp getpeerinfo
  var peers = newJArray()

  if rpc.peerManager != nil:
    var id = 0
    let now = getTime().toUnix()

    for peer in rpc.peerManager.getReadyPeers():
      # Calculate connection time in seconds
      let connTime = if peer.lastSeen.toUnix() > 0:
        now - (now - peer.lastSeen.toUnix())  # Connection start time
      else:
        now

      # Format services as hex string
      let servicesHex = toHex(cast[array[8, byte]]([
        byte(peer.services and 0xff),
        byte((peer.services shr 8) and 0xff),
        byte((peer.services shr 16) and 0xff),
        byte((peer.services shr 24) and 0xff),
        byte((peer.services shr 32) and 0xff),
        byte((peer.services shr 40) and 0xff),
        byte((peer.services shr 48) and 0xff),
        byte((peer.services shr 56) and 0xff)
      ]))

      # Build services names
      var servicesNames = newJArray()
      if (peer.services and 1) != 0:
        servicesNames.add(%"NETWORK")
      if (peer.services and 8) != 0:
        servicesNames.add(%"WITNESS")
      if (peer.services and 1024) != 0:
        servicesNames.add(%"NETWORK_LIMITED")

      # Calculate ping time in seconds
      let pingTime = if peer.latencyMs > 0:
        float64(peer.latencyMs) / 1000.0
      else:
        0.0

      # G14 (W115 FIX-50): compute mapped_as via ASMap when available.
      # Core: net.cpp:3813  vstats.back().m_mapped_as = GetMappedAS(pnode->addr)
      let mappedAs: uint32 =
        if rpc.netGroupManager != nil and rpc.netGroupManager.usingAsmap:
          let ip = parseIpAddr(peer.address)
          getMappedAS(rpc.netGroupManager, ip)
        else:
          0'u32

      peers.add(%*{
        "id": id,
        "addr": peer.address & ":" & $peer.port,
        "services": servicesHex,
        "servicesnames": servicesNames,
        "relaytxes": peer.relay,
        # Core v31.99 emits last_inv_sequence + inv_to_send between relaytxes and
        # lastsend (rpc/net.cpp:242-245). nimrod tracks neither at the manager
        # layer, so emit 0 — same pattern as addr_processed/addr_rate_limited
        # (and Core itself for peers without a CNodeStateStats).
        "last_inv_sequence": 0,
        "inv_to_send": 0,
        "lastsend": peer.lastSeen.toUnix(),
        "lastrecv": peer.lastSeen.toUnix(),
        "last_transaction": 0,
        "last_block": 0,
        "bytessent": peer.bytesSent,
        "bytesrecv": peer.bytesRecv,
        "conntime": connTime,
        "timeoffset": peer.timeOffset,
        "pingtime": pingTime,
        "minping": pingTime,
        "version": peer.version,
        "subver": peer.userAgent,
        "inbound": peer.direction == pdInbound,
        "bip152_hb_to": false,
        "bip152_hb_from": false,
        # Core v31.99 removed startingheight from getpeerinfo (rpc/net.cpp emits
        # presynced_headers directly after bip152_hb_from; m_starting_height is no
        # longer surfaced via RPC). Dropped for wire parity.
        "presynced_headers": -1,
        "synced_headers": rpc.chainState.bestHeight,
        "synced_blocks": rpc.chainState.bestHeight,
        "inflight": newJArray(),
        "addr_relay_enabled": true,
        "addr_processed": 0,
        "addr_rate_limited": 0,
        "permissions": newJArray(),
        "minfeefilter": float64(peer.feeFilterRate) / 100000000.0,
        "bytessent_per_msg": newJObject(),
        "bytesrecv_per_msg": newJObject(),
        "connection_type": (if peer.direction == pdInbound: "inbound" else: "outbound-full-relay"),
        "transport_protocol_type": "v1",
        "session_id": "",
        "mapped_as": mappedAs
      })
      inc id

  peers

proc handleGetNodeAddresses(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Return known addresses from the address manager, after filtering by network.
  ## Read-only addrman dump. Byte-faithful to Bitcoin Core
  ## (bitcoin-core/src/rpc/net.cpp:911-967 getnodeaddresses):
  ##   getnodeaddresses ( count "network" )  — both args optional.
  ##
  ## Returns a JSON ARRAY of objects, each with EXACTLY 5 keys in THIS ORDER:
  ##   time     NUM_TIME — unix seconds as an INTEGER
  ##   services NUM      — raw services bitfield as an INTEGER (not a hex string)
  ##   address  STR      — ToStringAddr (ip literal / .onion / .b32.i2p, no port)
  ##   port     NUM      — integer
  ##   network  STR      — ipv4|ipv6|onion|i2p|cjdns|not_publicly_routable|internal
  ##
  ## count (positional 0, default 1): MAX to return; 0 = all. count < 0 → -8.
  ## network (positional 1, optional, default all): ParseNetwork lowercases and
  ## accepts ONLY ipv4|ipv6|onion|i2p|cjdns; any other → -8 "Network not
  ## recognized: <raw>". The result is shuffled (non-deterministic order).

  # 1. count (default 1; 0 = all). Negative → RPC_INVALID_PARAMETER (-8).
  let hasCount = params.len >= 1 and params[0].kind != JNull
  let count = if hasCount: params[0].getInt() else: 1
  if count < 0:
    raise newRpcError(RpcInvalidParameter, "Address count out of range")

  # 2. network filter (optional). ParseNetwork: lowercase; only the 5 routable
  #    networks are valid INPUT filters. Anything else → -8.
  var networkFilter = none(string)
  let hasNetwork = params.len >= 2 and params[1].kind != JNull
  if hasNetwork:
    let raw = params[1].getStr()
    let net = raw.toLowerAscii()
    if net notin ["ipv4", "ipv6", "onion", "i2p", "cjdns"]:
      raise newRpcError(RpcInvalidParameter, "Network not recognized: " & raw)
    networkFilter = some(net)

  result = newJArray()
  if rpc.peerManager == nil:
    return  # no addrman → empty array (NOT an error), matching a fresh node

  for entry in rpc.peerManager.dumpKnownAddresses(count, networkFilter):
    var obj = newJObject()
    obj["time"] = %entry.time
    obj["services"] = %entry.services
    obj["address"] = %entry.address
    obj["port"] = %int(entry.port)
    obj["network"] = %entry.network
    result.add(obj)

proc handleAddPeerAddress(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Add the address of a potential peer to the address manager. Testing-only,
  ## the natural companion to getnodeaddresses. Core-shaped
  ## (bitcoin-core/src/rpc/net.cpp:972-1027 addpeeraddress):
  ##   addpeeraddress "address" port ( tried )
  ## Returns {"success": bool} (+ optional "error" on failure).
  if params.len < 2:
    raise newRpcError(RpcInvalidParameter, "address and port are required")

  let addrString = params[0].getStr()
  let port = uint16(params[1].getInt())
  # `tried` (params[2], optional, default false): when true the address is also
  # promoted NEW->TRIED in the bucketed addrman (Core marks it Good), so it
  # lands in the tried table that getaddrmaninfo reports.
  var tried = false
  if params.len >= 3 and params[2].kind != JNull:
    tried = params[2].getBool()

  # Optional `services` (positional 3) — lets the differential set a known
  # services bitfield. Core hardcodes NODE_NETWORK|NODE_WITNESS; we default to
  # the same (1 | 8 = 9) when omitted.
  var services: uint64 = 0x01'u64 or 0x08'u64
  if params.len >= 4 and params[3].kind != JNull:
    services = uint64(params[3].getBiggestInt())

  var obj = newJObject()
  if rpc.peerManager == nil:
    obj["success"] = %false
    obj["error"] = %"peer manager not available"
    return obj

  let ok = rpc.peerManager.injectKnownAddress(
    addrString, port, services, uint32(epochTime().int), tried)
  obj["success"] = %ok
  if not ok:
    obj["error"] = %"Invalid or non-routable IP address"
  obj

proc handleGetAddrmanInfo(rpc: RpcServer): JsonNode =
  ## Provide information about the node's address manager: per-network counts
  ## of addresses in the `new` and `tried` tables plus their sum.
  ## Byte-shape-faithful to Bitcoin Core (bitcoin-core/src/rpc/net.cpp:1080-1117
  ## getaddrmaninfo + AddrMan::Size addrman.cpp:1006-1026).
  ##
  ## Params: NONE. Pure read-only snapshot of the addrman — no side effects, no
  ## peers/sockets/disk touched.
  ##
  ## Returns a JSON OBJECT keyed by network name. The key set is FIXED and
  ## always present (every routable network emitted unconditionally, even at
  ## count 0), in Core's enum order:
  ##     ipv4, ipv6, onion, i2p, cjdns, all_networks
  ## Each value is an object with exactly three integer keys in order:
  ##     { "new":   <count in new table for this network>,
  ##       "tried": <count in tried table for this network>,
  ##       "total": <new + tried> }
  ## `all_networks` is the global sum across networks. NET_UNROUTABLE
  ## (not_publicly_routable) and NET_INTERNAL (internal) are never emitted,
  ## matching Core's loop that skips those two enum values.
  ##
  ## Invariants (oracle-free): per network total == new + tried;
  ## all_networks.{new,tried,total} == Σ networks.{new,tried,total}.

  # Fixed routable-network key order (Core enum NET_IPV4..NET_CJDNS, skipping
  # NET_UNROUTABLE / NET_INTERNAL). Every key is emitted even when the count is
  # zero — an IPv4-only node still reports onion/i2p/cjdns as 0/0/0.
  const networkKeys = ["ipv4", "ipv6", "onion", "i2p", "cjdns"]

  # Pre-seed all routable networks at zero so the key set is always complete,
  # then merge in the addrman's per-network split.
  var counts = initTable[string, tuple[newCount, triedCount: int]]()
  for k in networkKeys:
    counts[k] = (0, 0)

  if rpc.peerManager != nil:
    for name, c in rpc.peerManager.addrmanNetworkCounts():
      if counts.hasKey(name):
        var cur = counts[name]
        cur.newCount += c.newCount
        cur.triedCount += c.triedCount
        counts[name] = cur

  result = newJObject()
  var totalNew = 0
  var totalTried = 0
  for k in networkKeys:
    let nNew = counts[k].newCount
    let nTried = counts[k].triedCount
    var obj = newJObject()
    obj["new"] = %nNew
    obj["tried"] = %nTried
    obj["total"] = %(nNew + nTried)
    result[k] = obj
    totalNew += nNew
    totalTried += nTried

  var allObj = newJObject()
  allObj["new"] = %totalNew
  allObj["tried"] = %totalTried
  allObj["total"] = %(totalNew + totalTried)
  result["all_networks"] = allObj

proc handleGetConnectionCount(rpc: RpcServer): JsonNode =
  if rpc.peerManager != nil:
    %rpc.peerManager.connectedPeerCount()
  else:
    %0

proc handleGetNetTotals(rpc: RpcServer): JsonNode =
  ## getnettotals
  ## Reference: bitcoin-core/src/rpc/net.cpp::getnettotals (560)
  ##
  ## Core returns CConnman::GetTotalBytesRecv()/GetTotalBytesSent(), which are
  ## GLOBAL cumulative counters across ALL connections including disconnected
  ## peers. nimrod maintains only per-peer bytesSent/bytesRecv (the same
  ## counters getpeerinfo surfaces) and has no manager-level cumulative total
  ## that survives a disconnect, so we SUM the currently-connected peers. This
  ## is an APPROXIMATION (bytes from departed peers are not retained) and is
  ## noted as such — same data source as getpeerinfo's bytessent/bytesrecv.
  var totalRecv: uint64 = 0
  var totalSent: uint64 = 0
  if rpc.peerManager != nil:
    for peer in rpc.peerManager.getReadyPeers():
      totalRecv += peer.bytesRecv
      totalSent += peer.bytesSent

  # timemillis: current unix epoch in milliseconds (Core SystemClock::now()).
  let nowMs = int64(epochTime() * 1000.0)

  # uploadtarget: nimrod has no -maxuploadtarget, so emit the Core-faithful
  # zero shape (net.cpp with nMaxOutboundLimit==0): target 0, not reached,
  # serving historical blocks, nothing left to count in the cycle.
  result = %*{
    "totalbytesrecv": totalRecv,
    "totalbytessent": totalSent,
    "timemillis": nowMs,
    "uploadtarget": {
      "timeframe": 86400,            # Core DEFAULT_MAX_UPLOAD_TIMEFRAME (24h)
      "target": 0,
      "target_reached": false,
      "serve_historical_blocks": true,
      "bytes_left_in_cycle": 0,
      "time_left_in_cycle": 0
    }
  }

proc handleAddNode(rpc: RpcServer, params: JsonNode): JsonNode =
  if params.len < 2:
    raise newRpcError(RpcInvalidParams, "missing node and command parameters")

  let node = params[0].getStr()
  let command = params[1].getStr()

  if rpc.peerManager == nil:
    raise newRpcError(RpcInternalError, "peer manager not available")

  # Parse node address
  var host = node
  var port = rpc.params.defaultPort

  let colonIdx = node.rfind(':')
  if colonIdx > 0:
    host = node[0 ..< colonIdx]
    try:
      port = uint16(parseInt(node[colonIdx + 1 .. ^1]))
    except ValueError:
      raise newRpcError(RpcInvalidParams, "invalid port number")

  proc connectAsync(pm: PeerManager, h: string, p: uint16) {.async.} =
    # addnode peers are MANUAL connections (Core CConnman::ConnectNode with
    # ConnectionType::MANUAL): they bypass the automatic-outbound routability
    # gate (RFC1918/loopback skip) and slot limits, so an operator can force-dial
    # a specific peer — including a loopback peer for testing. Using the
    # full-relay path here silently dropped loopback addnode dials at the
    # isRoutable() gate.
    discard await pm.connectManualPeer(h, p)

  case command
  of "add":
    # Core rpc/net.cpp::addnode "add" raises RPC_CLIENT_NODE_ALREADY_ADDED (-23)
    # when the node is already on the added-node list (CConnman::AddNode returns
    # false). Record by the operator-supplied string (keyed on host:port here),
    # and only initiate the connect on a fresh add — matching the previous
    # success-path side effect.
    if not rpc.peerManager.addAddedNode(node):
      raise newRpcError(RpcClientNodeAlreadyAdded, "Error: Node already added")
    asyncSpawn connectAsync(rpc.peerManager, host, port)
  of "remove":
    # Core rpc/net.cpp::addnode "remove" raises RPC_CLIENT_NODE_NOT_ADDED (-24)
    # when the node was never added (CConnman::RemoveAddedNode returns false).
    if not rpc.peerManager.removeAddedNode(node):
      raise newRpcError(RpcClientNodeNotAdded,
        "Error: Node could not be removed. It has not been added previously.")
    for peer in rpc.peerManager.getReadyPeers():
      if peer.address == host and peer.port == port:
        asyncSpawn rpc.peerManager.removePeer(peer)
        break
  of "onetry":
    # Core's "onetry" does NOT touch the added-node list (net.cpp:352-357); it
    # only opens a one-off MANUAL connection.
    asyncSpawn connectAsync(rpc.peerManager, host, port)
  else:
    raise newRpcError(RpcInvalidParams, "invalid command: " & command)

  newJNull()

proc handleGetAddedNodeInfo(rpc: RpcServer, params: JsonNode): JsonNode =
  ## getaddednodeinfo ( "node" )
  ## Return information about the persistent `addnode`-managed list.
  ##
  ## Reference: Bitcoin Core rpc/net.cpp getaddednodeinfo (:486-558) +
  ## CConnman::GetAddedNodeInfo (net.cpp:2914). Mirrors Core's exact shape:
  ##
  ##   [ { "addednode": <str>,          # node as provided to addnode
  ##       "connected": <bool>,         # a current peer matches
  ##       "addresses": [               # ALWAYS present; [] when not connected
  ##         { "address": <str ip:port>,
  ##           "connected": "inbound" | "outbound" } ] },  # at most ONE entry
  ##     ... ]
  ##
  ## Param:
  ##   node (str, OPTIONAL): if provided, return only the matching added node.
  ##     Matching is exact-string equality against the value originally passed
  ##     to `addnode` (Core: m_params.m_added_node == node). If it is NOT on the
  ##     added list, raise -24 RPC_CLIENT_NODE_NOT_ADDED with the EXACT message
  ##     "Error: Node has not been added." (net.cpp:534). If omitted, all added
  ##     nodes are returned ([] when none). `onetry` adds are NOT on the list
  ##     (Core parity — net.cpp:352-357; nimrod's handleAddNode "onetry" path
  ##     does not touch addedNodes).
  ##
  ## nimrod stores the added-node registry as PeerManager.addedNodes, keyed by
  ## the EXACT operator-supplied string (CConnman::m_added_node_params
  ## equivalent). The `addednode` field reports that raw string. The optional
  ## `node` filter matches it by exact string equality (Core), with a
  ## normalized "host:port" fallback so `getaddednodeinfo "1.2.3.4"` also
  ## matches a node added as "1.2.3.4:<defaultPort>". Pure read — no side
  ## effects.

  # EnsureConnman parity (server_util.cpp): a missing peer manager is a hard
  # error, not an empty success.
  if rpc.peerManager == nil:
    raise newRpcError(RpcInternalError, "peer manager not available")

  # Normalize a "host[:port]" string to the canonical "host:port" key form
  # the live peer table uses (address & ":" & port), appending the default
  # P2P port when none is supplied. Mirrors handleAddNode's host/port parse.
  proc normalizeKey(nodeAddr: string): string =
    let colonIdx = nodeAddr.rfind(':')
    if colonIdx > 0:
      let host = nodeAddr[0 ..< colonIdx]
      try:
        let port = uint16(parseInt(nodeAddr[colonIdx + 1 .. ^1]))
        return host & ":" & $port
      except ValueError:
        return nodeAddr  # malformed: leave as-is; it just won't join a peer
    nodeAddr & ":" & $rpc.params.defaultPort

  # Snapshot the persistent added-node list. Insertion order is preserved
  # (Core outputs m_added_node_params in insertion order).
  var addedKeys = rpc.peerManager.addedNodesList()

  # Build a lookup of currently-connected peers keyed by "host:port" -> inbound?
  # (Core builds maps keyed by resolved CService and by addr_name.)
  var connected = initTable[string, bool]()
  for peer in rpc.peerManager.getReadyPeers():
    connected[peer.address & ":" & $peer.port] = (peer.direction == pdInbound)

  # Optional `node` filter: exact-string match against the raw added list
  # (Core net.cpp:529-535), with a normalized "host:port" fallback so a
  # port-appended stored entry matches a bare-host filter and vice versa.
  if params.len >= 1 and params[0].kind != JNull:
    if params[0].kind != JString:
      raise newRpcError(RpcTypeError,
        "JSON value of type " & $params[0].kind & " is not of expected type string")
    let want = params[0].getStr()
    var matched = ""
    var found = false
    for k in addedKeys:
      if k == want:
        matched = k
        found = true
        break
    if not found:
      let wantNorm = normalizeKey(want)
      for k in addedKeys:
        if normalizeKey(k) == wantNorm:
          matched = k
          found = true
          break
    if not found:
      # Core net.cpp:534 — EXACT message, leading "Error: ", trailing period.
      raise newRpcError(RpcClientNodeNotAdded, "Error: Node has not been added.")
    addedKeys = @[matched]

  var ret = newJArray()
  for key in addedKeys:
    let liveKey = normalizeKey(key)
    let isConnected = connected.hasKey(liveKey)
    var addresses = newJArray()
    if isConnected:
      addresses.add(%*{
        "address": liveKey,
        # Bare direction string per Core net.cpp:548 — "inbound"/"outbound",
        # NOT "manual"/"feeler".
        "connected": (if connected[liveKey]: "inbound" else: "outbound"),
      })
    ret.add(%*{
      "addednode": key,
      "connected": isConnected,
      "addresses": addresses,
    })
  ret

# Mining RPCs
proc handleGetBlockTemplate(rpc: RpcServer, params: JsonNode): JsonNode =
  # Build a minimal coinbase script (OP_TRUE for regtest/testing)
  var coinbaseScript = @[0x51'u8]  # OP_1

  # Get template params if provided
  if params.len >= 1 and params[0].kind == JObject:
    discard  # Could parse rules, capabilities, etc.

  let tmpl = buildBlockTemplate(
    rpc.chainState,
    rpc.mempool,
    rpc.params,
    coinbaseScript
  )

  var txs = newJArray()
  # Skip coinbase (index 0), add remaining transactions
  for i in 1 ..< tmpl.transactions.len:
    let tx = tmpl.transactions[i]
    let txid = tx.txid()
    let entry = rpc.mempool.get(txid)
    let fee = if entry.isSome: int64(entry.get().fee) else: 0'i64

    txs.add(%*{
      "data": toHex(serialize(tx)),
      "txid": reverseHex(toHex(array[32, byte](txid))),
      "hash": reverseHex(toHex(array[32, byte](tx.wtxid()))),
      "fee": fee,
      "sigops": estimateTxSigops(tx),
      "weight": validation.calculateTransactionWeight(tx)
    })

  # BUG-22 fix: compute rules array dynamically.
  # Bitcoin Core mining.cpp:950-958: always "csv"; if segwit active add "!segwit"
  # and "taproot" when taproot is active at this height.
  # Taproot is a buried deployment — check taprootHeight directly.
  let taprootActive = tmpl.height > rpc.params.taprootHeight
  var rulesArr = newJArray()
  rulesArr.add(%"csv")
  # segwit is active on all supported networks at practical heights
  if rpc.params.segwitHeight < tmpl.height:
    rulesArr.add(%"!segwit")
  if taprootActive:
    rulesArr.add(%"taproot")

  # BUG-2 fix: build vbavailable from STARTED and LOCKED_IN versionbits deployments.
  # Bitcoin Core mining.cpp:965-983: iterate gbtstatus.signalling + locked_in.
  # Only live BIP-9 versionbits deployments are in getDeployments(); taproot is buried.
  let deployments = getDeployments(rpc.params.network)
  let getBlockIndexFn = proc(h: BlockHash): Option[BlockIndex] =
    rpc.chainState.db.getBlockIndex(h)
  let getMtpFn = proc(h: BlockHash): int64 =
    getMtpForBlock(h, getBlockIndexFn)
  var vbCaches = newSeq[Table[BlockHash, ThresholdState]]()
  var vbavailableObj = newJObject()
  for i, dep in deployments:
    if i >= vbCaches.len:
      vbCaches.add(initTable[BlockHash, ThresholdState]())
    let state = getStateFor(dep, tmpl.header.prevBlock, getBlockIndexFn, getMtpFn, vbCaches[i])
    if state == tsStarted or state == tsLockedIn:
      vbavailableObj[dep.name] = %dep.bit

  # BUG-3 fix: vbrequired — Bitcoin Core always emits 0 (mining.cpp:996).
  let vbrequired = 0

  %*{
    "capabilities": ["proposal"],
    "version": tmpl.header.version,
    "rules": rulesArr,
    "vbavailable": vbavailableObj,
    "vbrequired": vbrequired,
    "previousblockhash": reverseHex(toHex(array[32, byte](tmpl.header.prevBlock))),
    "transactions": txs,
    "coinbaseaux": %*{},
    "coinbasevalue": int64(tmpl.totalFees) + int64(getBlockSubsidy(int32(tmpl.height), rpc.params)),
    "target": reverseHex(toHex(tmpl.target)),
    "mintime": tmpl.header.timestamp,
    "mutable": ["time", "transactions", "prevblock"],
    "noncerange": "00000000ffffffff",
    "sigoplimit": MaxBlockSigopsCost,
    "sizelimit": 4000000,
    "weightlimit": rpc.params.maxBlockWeight,
    "curtime": tmpl.header.timestamp,
    "bits": toHex(cast[array[4, byte]]([
      byte(tmpl.header.bits and 0xff),
      byte((tmpl.header.bits shr 8) and 0xff),
      byte((tmpl.header.bits shr 16) and 0xff),
      byte((tmpl.header.bits shr 24) and 0xff)
    ])),
    "height": tmpl.height,
    "default_witness_commitment": toHex(@[0x6a'u8, 0x24, 0xaa, 0x21, 0xa9, 0xed] & @(computeWitnessCommitment(tmpl.transactions)))
  }

proc bip22ChainError(errMsg: string): string =
  ## Map a chainstate error string to a BIP-22 result token.
  ## Chainstate errors are free-form strings; we look for known substrings.
  if "missing input" in errMsg or "missing or spent" in errMsg:
    return "bad-txns-inputs-missingorspent"
  if "immature coinbase" in errMsg:
    return "bad-txns-premature-spend-of-coinbase"
  if "duplicate" in errMsg:
    return "bad-txns-duplicate"
  return "rejected"

proc handleSubmitBlock(rpc: RpcServer, params: JsonNode): JsonNode =
  # NetworkDisable gate. Refuse submissions while a `dumptxoutset
  # rollback` dance is in progress. Mirrors Bitcoin Core's NetworkDisable
  # RAII around TemporaryRollback in rpc/blockchain.cpp::dumptxoutset.
  if rpc.isBlockSubmissionPaused():
    return %"rejected: block submission paused (dumptxoutset rollback in progress)"

  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing hexdata parameter")

  let blockHex = params[0].getStr()

  try:
    let blockBytes = hexToBytes(blockHex)
    let blk = deserializeBlock(blockBytes)

    # Full block validation (PoW, merkle root, transaction structure).
    # Reference: Bitcoin Core ProcessNewBlock -> CheckBlock.
    # Return canonical BIP-22 result strings per BIP-22 and Bitcoin Core
    # BIP22ValidationResult() in src/rpc/mining.cpp.
    let checkResult = checkBlock(blk, rpc.params)
    if not checkResult.isOk:
      return %bip22String(checkResult.error)

    # Check prevhash connects to a known block
    # Reference: Bitcoin Core AcceptBlockHeader -> check prev block exists
    var cs = rpc.chainState
    let prevHash = blk.header.prevBlock

    if prevHash == cs.bestBlockHash:
      # Block extends the current best chain — connect it
      let height = cs.bestHeight + 1

      # BIP-113 / Core ContextualCheckBlockHeader (validation.cpp:4092):
      # block timestamp must be strictly greater than the median-time-past
      # of the previous 11 blocks. getMtpForHeight uses the DB to walk the
      # last 11 ancestors. Genesis blocks (height 0) are skipped because
      # cs.bestHeight is -1 for an empty chain.
      # Reference: bitcoin-core/src/validation.cpp:4092
      if cs.bestHeight >= 0:
        let prevMtp = getMtpForHeight(cs.db, cs.bestHeight)
        if blk.header.timestamp <= prevMtp:
          return %bip22String(veBadTimestamp)

      # Contextual block validation: BIP-34 coinbase height, BIP-65/66,
      # script verification, etc. Requires the prevIndex for height context.
      # Reference: Bitcoin Core ContextualCheckBlock (validation.cpp:4130+).
      let prevIndexOpt = if cs.bestHeight < 0:
        # Genesis: no prevIndex in DB; build a sentinel with height=-1.
        some(BlockIndex(height: -1'i32))
      else:
        cs.db.getBlockIndex(prevHash)
      if prevIndexOpt.isNone:
        return %"prev-block-index-missing"
      let prevIdx = prevIndexOpt.get()

      # Unified consensus check pipeline (Core ProcessNewBlock parity):
      # checkBlock → validateBlock → checkBip30 → verifyScripts (gated on
      # skipScripts).  All three nimrod block-acceptance entry points delegate
      # to this single helper; structural divergence between paths is impossible.
      # Reference: bitcoin-core/src/validation.cpp::Chainstate::ProcessNewBlock.
      let skipScripts = cs.params.assumeValidHeight > 0 and
                        height <= cs.params.assumeValidHeight
      let utxoForAccept = proc(op: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].} =
        try: cs.getUtxo(op)
        except: none(UtxoEntry)
      let acceptResult = acceptBlock(blk, prevIdx, cs.db, cs.params,
                                     skipScripts = skipScripts,
                                     checkPow = false,  # PoW already checked by checkBlock above
                                     getUtxo = utxoForAccept,
                                     crypto = rpc.crypto)
      if not acceptResult.isOk:
        return %bip22String(acceptResult.error)

      # Use IBD fast path when far from tip (>1000 blocks behind assume-valid)
      let useIBD = cs.params.assumeValidHeight > 0 and
                   height < cs.params.assumeValidHeight - 1000
      if useIBD and not cs.ibdMode:
        cs.startIBD()
      elif not useIBD and cs.ibdMode:
        cs.stopIBD()

      # Capture undo BEFORE connect mutates the UTXO cache (BIP-157
      # filter elements need spent-prevout scriptPubKeys; the IBD fast
      # path does not write undo to disk).  No-op when filter index is
      # off, so cost is paid only when --blockfilterindex is enabled.
      var undoForFilter = chainstate.BlockUndo()
      let captureUndo = (rpc.filterIndex != nil and rpc.filterIndex.enabled) or
                        (rpc.coinStatsIndex != nil and rpc.coinStatsIndex.enabled)
      if captureUndo:
        undoForFilter = cs.generateBlockUndo(blk)

      let connectResult = if cs.ibdMode:
                            cs.connectBlockIBD(blk, height)
                          else:
                            cs.connectBlock(blk, height)

      if not connectResult.isOk:
        # Map chainstate error string to BIP-22 token
        return %bip22ChainError(connectResult.error)

      # Optional index population (no-op when nil/disabled).  Both the BIP-157
      # filter index and the coinstatsindex are folded forward here, mirroring
      # the live-sync connectBlock fan-out.
      if captureUndo:
        let bHdr = serialize(blk.header)
        let bHash = BlockHash(doubleSha256(bHdr))
        discard rpc.filterIndex.addBlock(blk, bHash, height, undoForFilter)
        discard rpc.coinStatsIndex.addBlock(blk, bHash, height, undoForFilter)

      # Fan out to the txospenderindex (no-op when nil/disabled).  It needs no
      # undo data (keys derive from the block's own inputs), so it is fed
      # OUTSIDE the captureUndo gate — enabling --txospenderindex alone must
      # populate it even with filter/coinstats off.
      if rpc.txoSpenderIndex != nil and rpc.txoSpenderIndex.enabled:
        let bHash2 = BlockHash(doubleSha256(serialize(blk.header)))
        discard rpc.txoSpenderIndex.addBlock(blk, bHash2, height, chainstate.BlockUndo())

      if not cs.ibdMode:
        # Remove confirmed transactions from mempool
        var mp = rpc.mempool
        mp.removeForBlock(blk)

        # Update fee estimator
        if rpc.feeEstimator != nil:
          var confirmedTxids: seq[TxId]
          for tx in blk.txs:
            confirmedTxids.add(tx.txid())
          rpc.feeEstimator.processBlock(height, confirmedTxids)

        # Wallet block-connect hook: a block accepted via submitblock (the
        # non-mining RPC path) must credit/debit + persist the wallet too,
        # not only generatetoaddress. DATA-LOSS FIX wa0fq5wtk — persists the
        # mutated ledger atomically. Best-effort inside the hook.
        rpc.scanBlockIntoWallets(blk, height)

        # Broadcast to peers
        if rpc.peerManager != nil:
          asyncSpawn rpc.peerManager.broadcastBlock(blk)

      newJNull()  # null = success per BIP-22

    else:
      # prevhash does not match current tip — this is a side-branch block.
      # Mirrors Bitcoin Core's `BlockManager::AcceptBlock` (validation.cpp):
      # every accepted block, whether on the active chain or a side-branch,
      # gets a CBlockIndex entry with cumulative chain_work and BLOCK_HAVE_DATA.
      # Storage and best-chain selection are decoupled.
      #
      # The store + work-compare + fork-point walk + reorg now lives in the
      # JSON-free chainstate.acceptSideBranchBlock so the P2P body path
      # (network/sync.nim) reaches the SAME reorg machinery (reorg-drop fix,
      # Part 2). This RPC arm builds the two injected consensus callbacks
      # (validate-for-storage + the per-promoted-block script-verify hook),
      # calls the proc, and maps its outcome back to BYTE-IDENTICAL BIP-22
      # tokens. Behaviour is verbatim with the former inline arm; the
      # corpus entry `regression/reorg-via-submitblock` must stay green.

      # validate-for-storage callback: full CheckBlock + ContextualCheckBlock
      # (scripts deferred to connect-time), bip22-mapped on failure. Wraps
      # consensus/validation.validateForStorage so chainstate (no validation
      # import) need not see ValidationError.
      let validateForSide = proc(b: Block, prevIdx: chainstate.BlockIndex):
                                 tuple[ok: bool, err: string] {.gcsafe, raises: [].} =
        var vr: ValidationResult[void]
        try:
          {.gcsafe.}:
            vr = validateForStorage(cs, b, prevIdx, rpc.crypto)
        except CatchableError:
          # Byte-identical with the old inline arm: an exception here used to
          # propagate to handleSubmitBlock's outer catch -> %"rejected".
          return (ok: false, err: "rejected")
        except Exception:
          return (ok: false, err: "rejected")
        if vr.isOk: (ok: true, err: "")
        else: (ok: false, err: bip22String(vr.error))

      # Per-promoted-block script-verify hook — `handleReorg` fires it against
      # the UTXO view it rebuilds to the fork point (Core ConnectTip ->
      # ConnectBlock parity). The hook reads UTXOs via `csCapture.getUtxo`,
      # which inside the reorg honours the in-flight reorgDeletedUtxos /
      # utxoCache / DB layering. Returning (ok: false) aborts the reorg and
      # leaves the original tip intact. `acceptSideBranchBlock` sets/clears
      # cs.reorgVerifyHook in a try/finally so it cannot leak.
      let csCapture = cs
      let reorgCrypto = rpc.crypto
      let reorgParams = cs.params
      let reorgVerify = proc(b: Block, height: int32): tuple[ok: bool, err: string]
                             {.gcsafe, raises: [].} =
        let utxoLookup = proc(op: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].} =
          try: csCapture.getUtxo(op)
          except: none(UtxoEntry)
        var res: ValidationResult[void]
        try:
          {.gcsafe.}:
            res = verifyScripts(b, utxoLookup, height, reorgCrypto, reorgParams)
        except CatchableError as e:
          return (ok: false, err: e.msg)
        except Exception as e:
          return (ok: false, err: e.msg)
        if res.isOk: (ok: true, err: "")
        else: (ok: false, err: bip22String(res.error))

      var disconnectedTxs: seq[Transaction] = @[]
      var newChainBlocks: seq[Block] = @[]
      let sideResult = acceptSideBranchBlock(cs, blk, validateForSide,
                                             reorgVerify, disconnectedTxs,
                                             newChainBlocks)

      # Map the outcome to byte-identical BIP-22 tokens:
      #   sboRejected  -> the carried token ("rejected" or bip22String(error))
      #   sboSideBranch -> "inconclusive" (stored, not best — or reorg deferred)
      #   sboReorged   -> success (JSON null) after the post-reorg refresh below.
      if sideResult.outcome == sboRejected or
         sideResult.outcome == sboSideBranch:
        return %sideResult.token

      # Reorg succeeded — refresh in-flight bookkeeping that the happy-path
      # arm normally handles. Mempool: refill disconnected non-coinbase txs
      # FIRST (Pattern B closure — mirrors Core's MaybeUpdateMempoolForReorg
      # via the disconnect-pool, and camlcoin sync.ml:2354-2363), then drop
      # confirmed transactions from the new tip's blocks (they were never
      # seen by the happy path because they arrived on a side-branch).  The
      # ordering matters when a tx appears in both the old and new chain:
      # the refill admits it, the subsequent removeForBlock drops it,
      # leaving the mempool with exactly the txs unique to the disconnected
      # chain.  Fee estimator: process each newly-connected block.  Peer
      # broadcast: relay the new tip.  Pattern B context:
      # CORE-PARITY-AUDIT/_mempool-refill-on-reorg-fleet-result-2026-05-05.md.
      var mp = rpc.mempool
      if disconnectedTxs.len > 0:
        let nReadmitted = mp.blockDisconnected(disconnectedTxs, rpc.crypto)
        debug "submitblock reorg: refilled mempool from disconnected blocks",
              attempted = disconnectedTxs.len, readmitted = nReadmitted
      for connected in newChainBlocks:
        mp.removeForBlock(connected)

      if rpc.feeEstimator != nil:
        var hAt = cs.bestHeight - int32(newChainBlocks.len) + 1
        for connected in newChainBlocks:
          var confirmedTxids: seq[TxId]
          for tx in connected.txs:
            confirmedTxids.add(tx.txid())
          rpc.feeEstimator.processBlock(hAt, confirmedTxids)
          inc hAt

      if rpc.peerManager != nil:
        asyncSpawn rpc.peerManager.broadcastBlock(blk)

      newJNull()  # null = success per BIP-22 (reorg activated this tip)

  except CatchableError as e:
    # Unexpected exception — use "rejected" catch-all per BIP-22.
    %"rejected"

proc handleSubmitHeader(rpc: RpcServer, params: JsonNode): JsonNode =
  ## submitheader "hexdata"
  ##
  ## Decode the given hexdata as an 80-byte block header and submit it as a
  ## candidate chain tip if valid. Throws when the header is invalid.
  ##
  ## Reference: bitcoin-core/src/rpc/mining.cpp submitheader() (RPCHelpMan).
  ## Byte-identical error semantics with Bitcoin Core:
  ##   * bad hex / wrong length  -> RPC_DESERIALIZATION_ERROR (-22)
  ##                                "Block header decode failed"
  ##   * parent unknown to node  -> RPC_VERIFY_ERROR (-25)
  ##                                "Must submit previous header (<prevhash>) first"
  ##                                where <prevhash> is the big-endian DISPLAY hex.
  ##   * PoW / contextual reject -> RPC_VERIFY_ERROR (-25) with the reject reason.
  ##   * success / already-known -> JSON null.
  ##
  ## This reuses nimrod's REAL headers-first validation path
  ## (validation.validateBlockHeader = Core CheckBlockHeader; and
  ## validation.contextualCheckBlockHeader = Core ContextualCheckBlockHeader),
  ## the same procs the live P2P/AcceptBlock path runs. No parallel validator.
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing hexdata parameter")

  let hexData = params[0].getStr()

  # --- Step 1: decode the hex-encoded 80-byte header ----------------------
  # Core: DecodeHexBlockHeader(h, request.params[0].get_str()):
  #   IsHex(hex)  (even length + all hex chars)  AND
  #   SpanReader{header_data} >> header           (needs >= 80 bytes; the
  #   fixed-width CBlockHeader unserialize ignores any trailing bytes).
  # Any failure -> RPC_DESERIALIZATION_ERROR -22 "Block header decode failed".
  var header: BlockHeader
  block decode:
    # IsHex parity: reject odd-length or non-hex.
    if hexData.len == 0 or (hexData.len mod 2) != 0:
      raise newRpcError(RpcDeserializationError, "Block header decode failed")
    for c in hexData:
      if c notin {'0'..'9', 'a'..'f', 'A'..'F'}:
        raise newRpcError(RpcDeserializationError, "Block header decode failed")
    var rawBytes: seq[byte]
    try:
      rawBytes = hexToBytes(hexData)
    except CatchableError:
      raise newRpcError(RpcDeserializationError, "Block header decode failed")
    # SpanReader >> CBlockHeader needs at least the 80 header bytes.
    if rawBytes.len < 80:
      raise newRpcError(RpcDeserializationError, "Block header decode failed")
    try:
      header = deserializeBlockHeader(rawBytes[0 ..< 80])
    except CatchableError:
      raise newRpcError(RpcDeserializationError, "Block header decode failed")

  # Compute this header's block hash (double-SHA256 of the 80-byte header,
  # internal little-endian order — nimrod's BlockHash, == Core's uint256).
  let headerBytes = serialize(header)
  let blockHash = BlockHash(doubleSha256(headerBytes))

  let cs = rpc.chainState
  let prevHash = header.prevBlock
  # Big-endian DISPLAY hex of prevhash, matching Core's h.hashPrevBlock.GetHex()
  # (reverses the internal little-endian bytes). Same convention every other
  # nimrod RPC uses for a block hash: reverseHex(toHex(<internal bytes>)).
  let prevHashDisplay = reverseHex(toHex(array[32, byte](prevHash)))

  # --- Step 2: parent-known check -----------------------------------------
  # Core: LOCK(cs_main); if (!chainman.m_blockman.LookupBlockIndex(h.hashPrevBlock))
  #   throw JSONRPCError(RPC_VERIFY_ERROR, "Must submit previous header (...) first").
  # nimrod's single block index (cfBlockIndex) holds active-chain AND side-branch
  # AND header-only entries (putBlockIndex / putBlockIndexHashOnly), so
  # cs.db.getBlockIndex is the faithful LookupBlockIndex analog: the active tip
  # is always indexed (connectBlock writes its row), and so is every header
  # previously admitted via Step 5 below.
  let prevIndexOpt = cs.db.getBlockIndex(prevHash)
  if prevIndexOpt.isNone:
    raise newRpcError(RpcTransactionError,
      "Must submit previous header (" & prevHashDisplay & ") first")
  let prevIndex = prevIndexOpt.get()

  # --- Step 3: idempotency ------------------------------------------------
  # Core's ProcessNewBlockHeaders is idempotent: a header already in the block
  # index is a no-op that returns null (AcceptBlockHeader's "miSelf != end" path).
  if cs.db.getBlockIndex(blockHash).isSome:
    return newJNull()

  # --- Step 4: real header validation -------------------------------------
  # Core: ProcessNewBlockHeaders -> AcceptBlockHeader -> CheckBlockHeader
  #       (PoW + time-too-new + prev-link) THEN ContextualCheckBlockHeader
  #       (bad-diffbits, time-too-old MTP, BIP-94 timewarp, bad-version).
  # Reuse nimrod's production procs for BOTH, in the same order:
  #   validateBlockHeader        == CheckBlockHeader
  #   contextualCheckBlockHeader == ContextualCheckBlockHeader
  # On failure throw RPC_VERIFY_ERROR (-25) with the bip22 reject reason, which
  # is Core's state.GetRejectReason() token (high-hash / bad-diffbits /
  # time-too-old / time-too-new / bad-version / time-timewarp-attack).
  let ctxFreeRes = validateBlockHeader(header, prevIndex, cs.params,
                                       checkPow = true, minPowChecked = true)
  if not ctxFreeRes.isOk:
    raise newRpcError(RpcTransactionError, bip22String(ctxFreeRes.error))

  let ctxRes = contextualCheckBlockHeader(header, prevIndex, cs.db, cs.params)
  if not ctxRes.isOk:
    raise newRpcError(RpcTransactionError, bip22String(ctxRes.error))

  # --- Step 5: admit the validated header into the block index ------------
  # Core's AcceptBlockHeader inserts the validated header into the block index
  # (CBlockIndex with BLOCK_VALID_TREE). Mirror that with a hash-only block
  # index row (the active height->hash slot is owned by the best chain; this is
  # a header, not a connected block), so the parent-known and idempotency checks
  # above see it on a subsequent submitheader. Cumulative work uses the SAME
  # canonical chainstate work-per-block helper (calculateBlockWork) the
  # side-branch arm uses, summed little-endian onto the parent's totalWork, so
  # the persisted totalWork is self-consistent with cs.totalWork (one work
  # universe). 256-bit LE add inlined here (chainstate's addWork is unexported,
  # and its name collides with network/sync's value-returning addWork).
  var hdrTotalWork = prevIndex.totalWork
  block addBlockWork:
    let blkWork = calculateBlockWork(header.bits)
    var carry: uint32 = 0
    for i in 0 ..< 32:
      let s = uint32(hdrTotalWork[i]) + uint32(blkWork[i]) + carry
      hdrTotalWork[i] = byte(s and 0xff)
      carry = s shr 8
  let hdrIdx = chainstate.BlockIndex(
    hash: blockHash,
    height: prevIndex.height + 1,
    status: bsHeaderOnly,
    prevHash: prevHash,
    header: header,
    totalWork: hdrTotalWork,
    undoPos: FlatFilePos(fileNum: -1, pos: -1),
    failureFlags: BLOCK_NO_FAILURE,
    sequenceId: 0,
    nTx: 0'i32
  )
  cs.db.putBlockIndexHashOnly(hdrIdx)

  newJNull()  # success per Core: ProcessNewBlockHeaders state.IsValid() -> VNULL

# ============================================================================
# Wallet block-connect hook
# ============================================================================
# The wallet keeps its own UTXO ledger (Wallet.utxos), credited/debited by
# wallet.scanBlockForWallet(). That proc was dead code — nothing ever called it
# from the chain — so getbalance/listunspent were always 0/[] and sendtoaddress
# died "no spendable UTXOs". Mirror Bitcoin Core's CWallet::blockConnected:
# every time a block connects to the active tip, scan it into every loaded
# wallet so wallet-owned coinbase/payment outputs are credited and spends of
# wallet coins are debited. Best-effort — a wallet bookkeeping failure must
# never roll back a fully-validated block (the ledger is reconstructible via
# scantxoutset / rescan). Wallet is a `ref object`, so mutating the instance the
# manager holds persists across RPC calls.

proc persistLoadedWallets(rpc: RpcServer) {.gcsafe.} =
  ## Atomically snapshot every loaded wallet to disk. DATA-LOSS FIX wa0fq5wtk:
  ## called after every state-changing wallet op (per-block scan credit/debit,
  ## getnewaddress keypool advance, setlabel, sendtoaddress) so an unclean
  ## exit (SIGKILL/OOM/power-loss) can never lose ledger state. Best-effort —
  ## a save failure is logged inside the persist layer and never throws.
  if rpc.walletManager != nil:
    try: rpc.walletManager.persistAllWallets()
    except CatchableError: discard

proc persistTargetWallet(rpc: RpcServer) {.gcsafe.} =
  ## Snapshot the wallet targeted by the current request after a mutating
  ## RPC (getnewaddress / setlabel / sendtoaddress …). DATA-LOSS FIX
  ## wa0fq5wtk: the keypool advance / label / spend must hit disk before the
  ## RPC returns so a crash right after the call cannot lose it. Best-effort.
  if rpc.walletManager != nil:
    try:
      if rpc.currentWalletName != "":
        discard rpc.walletManager.persistWallet(rpc.currentWalletName)
      else:
        # Default (single) wallet: persist whatever is loaded.
        rpc.walletManager.persistAllWallets()
    except CatchableError:
      discard

proc scanBlockIntoWallets(rpc: RpcServer, blk: Block, height: int32,
                          persist: bool) {.gcsafe.} =
  ## Credit/debit every loaded wallet's UTXO ledger from a connected block.
  ## Idempotent: re-scanning the same block re-inserts the same {txid,vout}
  ## entries (set semantics) and re-deletes already-absent spends (no-op).
  ## When `persist`, the (mutated) ledger is snapshotted to disk afterwards —
  ## the save-on-mutation half of the data-loss fix. Bulk callers pass
  ## persist=false and snapshot once at the end to avoid per-block fsync.
  if rpc.walletManager != nil:
    for name in rpc.walletManager.listLoadedWallets():
      let lwOpt = rpc.walletManager.getWallet(name)
      if lwOpt.isSome:
        var w = lwOpt.get().wallet
        if w != nil:
          try:
            w.scanBlockForWallet(blk, height)
          except CatchableError:
            discard  # never let wallet bookkeeping abort a valid block
    if persist:
      rpc.persistLoadedWallets()
  # Legacy single-wallet fallback (pre-walletManager deployments).
  elif rpc.wallet != nil:
    try:
      rpc.wallet.scanBlockForWallet(blk, height)
    except CatchableError:
      discard

proc scanConnectedBlocksIntoWallets(rpc: RpcServer, hashes: seq[BlockHash]) {.gcsafe.} =
  ## Scan a run of freshly-connected blocks (in connection order) into the
  ## wallet ledgers. `hashes` are the blocks just mined/connected, oldest first;
  ## the tip is at chainState.bestHeight after they all connected, so block i
  ## sits at height (bestHeight - (len-1-i)).
  let tip = rpc.chainState.bestHeight
  let n = hashes.len
  for i, h in hashes:
    let height = tip - int32(n - 1 - i)
    let blkOpt = rpc.chainState.db.getBlock(h)
    if blkOpt.isSome:
      # Defer the snapshot until all blocks scanned (one fsync, not n).
      rpc.scanBlockIntoWallets(blkOpt.get(), height, persist = false)
  rpc.persistLoadedWallets()

proc unscanBlockFromWallets(rpc: RpcServer, blk: Block, height: int32) {.gcsafe.} =
  ## Reverse of scanBlockIntoWallets for a block leaving the active chain
  ## (invalidateblock / reorg disconnect). Symmetric with the connect hook:
  ## drops the transaction-history records this block contributed to every
  ## loaded wallet so listtransactions/gettransaction never report a tx that
  ## is no longer in the active chain. Best-effort — a wallet bookkeeping
  ## failure must never abort the disconnect. The live UTXO ledger is
  ## reconstructible via scantxoutset, so we only revert the history here.
  if rpc.walletManager != nil:
    for name in rpc.walletManager.listLoadedWallets():
      let lwOpt = rpc.walletManager.getWallet(name)
      if lwOpt.isSome:
        var w = lwOpt.get().wallet
        if w != nil:
          try:
            w.unscanBlockForWallet(blk, height)
          except CatchableError:
            discard
  elif rpc.wallet != nil:
    try:
      rpc.wallet.unscanBlockForWallet(blk, height)
    except CatchableError:
      discard

# Regtest mining RPCs

proc handleGenerateToAddress(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Mine blocks with coinbase reward sent to specified address
  ## Reference: Bitcoin Core rpc/mining.cpp generatetoaddress
  ##
  ## Arguments:
  ## 1. nblocks (numeric, required) - How many blocks to generate
  ## 2. address (string, required) - Address to send coinbase reward to
  ## 3. maxtries (numeric, optional, default=1000000) - Max mining iterations
  ##
  ## Returns: Array of block hashes (hex strings, reversed display order)
  ##
  ## Note: Only available on regtest (powNoRetargeting = true)

  if not rpc.params.powNoRetargeting:
    raise newRpcError(RpcMiscError, "generate is only available on regtest")

  if params.len < 2:
    raise newRpcError(RpcInvalidParams, "missing nblocks or address parameter")

  let nblocks = params[0].getInt()
  if nblocks < 0:
    raise newRpcError(RpcInvalidParams, "nblocks must be non-negative")

  let address = params[1].getStr()
  let maxTries = if params.len >= 3: uint64(params[2].getInt()) else: DefaultMaxTries

  try:
    # Validate address
    discard decodeAddress(address)
  except AddressError:
    raise newRpcError(RpcInvalidAddressOrKey, "Invalid address")

  var cs = rpc.chainState
  var mp = rpc.mempool

  let hashes = generateToAddress(cs, mp, rpc.params, nblocks, address, maxTries)

  # BIP-157 filter index population (no-op when nil/disabled).  Core's BaseIndex
  # hooks BlockConnected for locally-mined blocks too — keep the index at the tip
  # so getindexinfo reports synced=true / best_block_height==tip after mining.
  rpc.populateFilterIndexForHashes(hashes)
  rpc.populateTxoSpenderIndexForHashes(hashes)

  # Wallet block-connect hook: credit/debit every loaded wallet from the blocks
  # just connected, so coinbase rewards paid to a wallet address (and any wallet
  # spends confirmed in these blocks) land in the wallet UTXO ledger. Mirrors
  # Bitcoin Core's CWallet::blockConnected. Without this, getbalance stays 0 and
  # sendtoaddress fails "no spendable UTXOs" even after generatetoaddress.
  rpc.scanConnectedBlocksIntoWallets(hashes)

  # Convert to JSON array of hex strings (reversed for display)
  var result = newJArray()
  for hash in hashes:
    result.add(%reverseHex(toHex(array[32, byte](hash))))

  # Update fee estimator for each block
  if rpc.feeEstimator != nil:
    for i, hash in hashes:
      let height = rpc.chainState.bestHeight - int32(hashes.len - 1 - i)
      # Get confirmed txids (simplified - just mark block processed)
      rpc.feeEstimator.processBlock(height, @[])

  # Broadcast new blocks to peers
  if rpc.peerManager != nil:
    for hash in hashes:
      let blkOpt = rpc.chainState.db.getBlock(hash)
      if blkOpt.isSome:
        asyncSpawn rpc.peerManager.broadcastBlock(blkOpt.get())

  result

proc handleGenerateToDescriptor(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Mine blocks with coinbase reward sent to specified descriptor
  ## Reference: Bitcoin Core rpc/mining.cpp generatetodescriptor
  ##
  ## Arguments:
  ## 1. num_blocks (numeric, required) - How many blocks to generate
  ## 2. descriptor (string, required) - Output descriptor for coinbase
  ## 3. maxtries (numeric, optional, default=1000000) - Max mining iterations
  ##
  ## Returns: Array of block hashes (hex strings)

  if not rpc.params.powNoRetargeting:
    raise newRpcError(RpcMiscError, "generate is only available on regtest")

  if params.len < 2:
    raise newRpcError(RpcInvalidParams, "missing num_blocks or descriptor parameter")

  let nblocks = params[0].getInt()
  if nblocks < 0:
    raise newRpcError(RpcInvalidParams, "num_blocks must be non-negative")

  let descriptorStr = params[1].getStr()
  let maxTries = if params.len >= 3: uint64(params[2].getInt()) else: DefaultMaxTries

  try:
    # Validate descriptor
    discard parseDescriptor(descriptorStr)
  except DescriptorError as e:
    raise newRpcError(RpcInvalidAddressOrKey, "Invalid descriptor: " & e.msg)

  var cs = rpc.chainState
  var mp = rpc.mempool

  let hashes = generateToDescriptor(cs, mp, rpc.params, nblocks, descriptorStr, maxTries)

  # BIP-157 filter index population (no-op when nil/disabled). See generatetoaddress.
  rpc.populateFilterIndexForHashes(hashes)
  rpc.populateTxoSpenderIndexForHashes(hashes)

  # Broadcast new blocks to peers
  if rpc.peerManager != nil:
    for hash in hashes:
      let blkOpt = rpc.chainState.db.getBlock(hash)
      if blkOpt.isSome:
        asyncSpawn rpc.peerManager.broadcastBlock(blkOpt.get())

  # Convert to JSON array of hex strings
  var result = newJArray()
  for hash in hashes:
    result.add(%reverseHex(toHex(array[32, byte](hash))))
  result

proc handleGenerateBlock(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Mine a block with specific transactions
  ## Reference: Bitcoin Core rpc/mining.cpp generateblock
  ##
  ## Arguments:
  ## 1. output (string, required) - Address or descriptor for coinbase
  ## 2. transactions (array, required) - Array of transaction hex strings or txids
  ##
  ## Returns:
  ## {
  ##   "hash": "blockhash"
  ## }

  if not rpc.params.powNoRetargeting:
    raise newRpcError(RpcMiscError, "generateblock is only available on regtest")

  if params.len < 2:
    raise newRpcError(RpcInvalidParams, "missing output or transactions parameter")

  let output = params[0].getStr()

  # Parse output to get coinbase script
  var coinbaseScript: seq[byte]
  try:
    # Try as address first
    let parsedAddr = decodeAddress(output)
    coinbaseScript = scriptPubKeyForAddress(parsedAddr)
  except AddressError:
    try:
      # Try as descriptor
      let desc = parseDescriptor(output)
      let scripts = desc.deriveScripts(0, 1)
      if scripts.len > 0:
        coinbaseScript = scripts[0]
      else:
        raise newRpcError(RpcInvalidAddressOrKey, "Descriptor produced no scripts")
    except DescriptorError as e:
      raise newRpcError(RpcInvalidAddressOrKey, "Invalid output: not a valid address or descriptor")

  # Parse transactions parameter
  var txids: seq[TxId]
  if params[1].kind != JArray:
    raise newRpcError(RpcInvalidParams, "transactions must be an array")

  for txParam in params[1]:
    let txStr = txParam.getStr()
    if txStr.len == 64:
      # Assume it's a txid
      txids.add(parseTxId(txStr))
    else:
      # Assume it's a raw transaction hex
      try:
        let txBytes = hexToBytes(txStr)
        let tx = deserializeTransaction(txBytes)
        let txid = tx.txid()

        # Add to mempool if not already there
        if rpc.mempool.get(txid).isNone:
          discard rpc.mempool.acceptTransaction(tx, rpc.crypto)

        txids.add(txid)
      except CatchableError as e:
        raise newRpcError(RpcInvalidParams, "invalid transaction: " & e.msg)

  var cs = rpc.chainState
  var mp = rpc.mempool

  let hashOpt = generateBlockWithTxs(cs, mp, rpc.params, coinbaseScript, txids, DefaultMaxTries)

  if hashOpt.isNone:
    raise newRpcError(RpcMiscError, "failed to generate block")

  let hash = hashOpt.get()

  # BIP-157 filter index population (no-op when nil/disabled). See generatetoaddress.
  rpc.populateFilterIndexForHashes(@[hash])
  rpc.populateTxoSpenderIndexForHashes(@[hash])

  # Broadcast new block
  if rpc.peerManager != nil:
    let blkOpt = rpc.chainState.db.getBlock(hash)
    if blkOpt.isSome:
      asyncSpawn rpc.peerManager.broadcastBlock(blkOpt.get())

  %*{
    "hash": reverseHex(toHex(array[32, byte](hash)))
  }

proc handleGenerate(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Deprecated - use generatetoaddress instead
  ## Reference: Bitcoin Core rpc/mining.cpp generate
  raise newRpcError(RpcMethodNotFound, "The generate method has been replaced by generatetoaddress. Refer to -help for more information.")

# Fee estimation RPC
proc handleEstimateSmartFee(rpc: RpcServer, params: JsonNode): JsonNode =
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing conf_target parameter")

  let confTarget = params[0].getInt()

  if confTarget < 1 or confTarget > 1008:
    raise newRpcError(RpcInvalidParams, "conf_target out of range (1-1008)")

  var feeRate: float64 = 0.0
  if rpc.feeEstimator != nil:
    feeRate = rpc.feeEstimator.estimateFee(confTarget)

  if feeRate <= 0:
    return %*{
      "errors": ["Insufficient data or no feerate found"],
      "blocks": confTarget
    }

  # Convert sat/vbyte to BTC/kB
  let feeBtcPerKb = feeRate * 1000.0 / 100000000.0

  %*{
    "feerate": feeBtcPerKb,
    "blocks": confTarget
  }

proc handleEstimateRawFee(rpc: RpcServer, params: JsonNode): JsonNode =
  ## estimaterawfee conf_target [threshold]
  ## Returns raw fee-estimator state per horizon.
  ##
  ## Reference: bitcoin-core/src/rpc/fees.cpp estimaterawfee.
  ## nimrod's FeeEstimator is a single-horizon histogram and does not split
  ## confirmations into short/medium/long like Core's CBlockPolicyEstimator;
  ## we expose the available bucket data under each horizon name with
  ## consistent shape so clients that just check `<horizon>.feerate` work.
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing conf_target parameter")

  let confTarget = params[0].getInt()
  if confTarget < 1 or confTarget > 1008:
    raise newRpcError(RpcInvalidParams, "conf_target out of range (1-1008)")

  var threshold = 0.95
  if params.len >= 2:
    case params[1].kind
    of JInt:    threshold = float64(params[1].getInt())
    of JFloat:  threshold = params[1].getFloat()
    of JNull:   discard
    else:
      raise newRpcError(RpcInvalidParams, "threshold must be a number")
  if threshold < 0 or threshold > 1:
    raise newRpcError(RpcInvalidParams, "Invalid threshold")

  proc horizonResult(rpc: RpcServer, hs: HorizonStats, target: int): JsonNode =
    ## Build one horizon's estimaterawfee result using its own bucket data.
    if rpc.feeEstimator == nil:
      return %*{
        "decay": hs.decay,
        "scale": hs.scale,
        "errors": ["fee estimator unavailable"]
      }
    let feeRate = estimateFeeForHorizon(hs, target)
    if feeRate <= 0.0:
      return %*{
        "decay": hs.decay,
        "scale": hs.scale,
        "errors": ["Insufficient data or no feerate found which meets threshold"]
      }
    let feeBtcPerKb = feeRate * 1000.0 / 100000000.0
    # Walk this horizon's buckets to populate "pass"/"fail" ranges
    var passStart = 0.0
    var passEnd = 0.0
    var passWithin = 0.0
    var passConfirmed = 0.0
    var failStart = -1.0
    var failEnd = 0.0
    var failWithin = 0.0
    var failConfirmed = 0.0
    var prevRate = 0.0
    for i in 0 ..< NumBuckets:
      let stats = getHorizonBucketStats(hs, i)
      if stats.totalSeen <= 0:
        prevRate = FeeRateBuckets[i]
        continue
      let rate = getConfirmationRateForHorizon(hs, i, target)
      let bucketEnd = FeeRateBuckets[i]
      if rate >= threshold:
        passStart = prevRate
        passEnd = bucketEnd
        passWithin = stats.totalSeen * rate
        passConfirmed = stats.totalSeen * rate
        break
      else:
        failStart = prevRate
        failEnd = bucketEnd
        failWithin = stats.totalSeen * rate
        failConfirmed = stats.totalSeen * rate
      prevRate = bucketEnd
    var horizon = %*{
      "feerate": feeBtcPerKb,
      "decay": hs.decay,
      "scale": hs.scale,
      "pass": {
        "startrange": passStart,
        "endrange": passEnd,
        "withintarget": passWithin,
        "totalconfirmed": passConfirmed,
        "inmempool": float64(rpc.feeEstimator.getTrackedCount()),
        "leftmempool": 0.0
      }
    }
    if failStart >= 0.0:
      horizon["fail"] = %*{
        "startrange": failStart,
        "endrange": failEnd,
        "withintarget": failWithin,
        "totalconfirmed": failConfirmed,
        "inmempool": 0.0,
        "leftmempool": 0.0
      }
    horizon

  # Three independent horizons — each uses its own decay/scale/bucket data
  if rpc.feeEstimator == nil:
    let errNode = %*{"errors": ["fee estimator unavailable"]}
    return %*{"short": errNode, "medium": errNode, "long": errNode}
  result = %*{
    "short":  horizonResult(rpc, rpc.feeEstimator.shortHorizon, confTarget),
    "medium": horizonResult(rpc, rpc.feeEstimator.medHorizon,   confTarget),
    "long":   horizonResult(rpc, rpc.feeEstimator.longHorizon,  confTarget)
  }

# Address validation RPC
# Ban management RPCs
proc handleListBanned(rpc: RpcServer): JsonNode =
  ## Return all currently banned addresses
  if rpc.peerManager == nil:
    return %*[]

  var banned = newJArray()
  for entry in rpc.peerManager.listBanned():
    banned.add(%*{
      "address": entry.address,
      "ban_created": entry.banCreated,
      "banned_until": entry.banUntil,
      "ban_reason": $entry.reason
    })
  banned

proc isValidIpv4Literal(s: string): bool =
  ## True iff `s` is a dotted-quad numeric IPv4 literal (four 0..255 octets).
  ## Mirrors the numeric-only acceptance of Core's LookupHost(.., allow_lookup
  ## = false) for the non-subnet setban argument (no DNS resolution).
  let parts = s.split('.')
  if parts.len != 4: return false
  for p in parts:
    if p.len == 0 or p.len > 3: return false
    for c in p:
      if c notin {'0'..'9'}: return false
    let v = try: parseInt(p) except ValueError: return false
    if v < 0 or v > 255: return false
  true

proc isValidIpv6Literal(s: string): bool =
  ## True iff `s` is a syntactically valid numeric IPv6 literal (incl. the
  ## "::" zero-run compression and a trailing IPv4-mapped tail). Conservative
  ## mirror of Core's CNetAddr IPv6 parse acceptance for setban; rejects empty
  ## / non-hex / over-length forms so a bad string is reported as -30.
  if s.len == 0: return false
  if ':' notin s: return false
  let doubleColon = s.count("::")
  if doubleColon > 1: return false
  var groups = s.split(':')
  # A trailing IPv4-mapped tail (e.g. ::ffff:1.2.3.4) counts as 2 16-bit groups.
  var ipv4Tail = false
  if groups.len > 0 and '.' in groups[^1]:
    if not isValidIpv4Literal(groups[^1]): return false
    ipv4Tail = true
    groups = groups[0 ..< ^1]
  var hexGroups = 0
  for g in groups:
    if g.len == 0: continue  # produced by leading/trailing/'::' empty splits
    if g.len > 4: return false
    for c in g:
      if c notin {'0'..'9', 'a'..'f', 'A'..'F'}: return false
    inc hexGroups
  let need = if ipv4Tail: 6 else: 8
  if doubleColon == 1:
    # Compressed form: must have fewer than the full complement of groups.
    return hexGroups <= (need - 1)
  else:
    return hexGroups == need

proc isValidBanSubnetArg(arg: string): bool =
  ## Validate the `setban` subnet/IP argument exactly at the boundary Core
  ## checks (rpc/net.cpp:765-781): a bare numeric IP, or "<ip>/<prefixlen>"
  ## CIDR. Returns false for anything that would make Core raise
  ## RPC_CLIENT_INVALID_IP_OR_SUBNET (-30). No DNS resolution (numeric only).
  if arg.len == 0: return false
  let slash = arg.find('/')
  if slash < 0:
    # Bare IP.
    return isValidIpv4Literal(arg) or isValidIpv6Literal(arg)
  # Subnet: <ip>/<prefixlen>.
  let ipPart = arg[0 ..< slash]
  let prefixPart = arg[slash + 1 .. ^1]
  if prefixPart.len == 0: return false
  for c in prefixPart:
    if c notin {'0'..'9'}: return false
  let prefix = try: parseInt(prefixPart) except ValueError: return false
  let isV4 = isValidIpv4Literal(ipPart)
  let isV6 = (not isV4) and isValidIpv6Literal(ipPart)
  if not (isV4 or isV6): return false
  let maxPrefix = if isV4: 32 else: 128
  prefix >= 0 and prefix <= maxPrefix

proc handleSetBan(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Add or remove a peer from the ban list
  ## setban "address" "add|remove" [bantime] [absolute]
  if params.len < 2:
    raise newRpcError(RpcInvalidParams, "missing required parameters: address, command")

  if rpc.peerManager == nil:
    raise newRpcError(RpcInternalError, "peer manager not available")

  let address = params[0].getStr()
  let command = params[1].getStr()

  # Core rpc/net.cpp::setban validates the subnet/IP argument (net.cpp:765-781)
  # and raises RPC_CLIENT_INVALID_IP_OR_SUBNET (-30) with this exact message
  # when it is neither a numeric IP nor a valid "<ip>/<prefix>" CIDR — for both
  # "add" and "remove" — before touching the ban list. Previously nimrod passed
  # the raw string straight through with no validation.
  if not isValidBanSubnetArg(address):
    raise newRpcError(RpcClientInvalidIpOrSubnet, "Error: Invalid IP/Subnet")

  case command
  of "add":
    var bantime = int64(24 * 60 * 60)  # Default 24 hours
    var absolute = false

    if params.len >= 3:
      bantime = params[2].getBiggestInt()
    if params.len >= 4:
      absolute = params[3].getBool()

    if absolute:
      # bantime is absolute unix timestamp
      rpc.peerManager.banManager.banAbsolute(address, bantime, brManuallyAdded)
    else:
      # bantime is relative duration in seconds
      let duration = initDuration(seconds = bantime)
      rpc.peerManager.banPeer(address, duration, brManuallyAdded)

  of "remove":
    if not rpc.peerManager.unbanPeer(address):
      raise newRpcError(RpcInvalidParams, "address not found in ban list")

  else:
    raise newRpcError(RpcInvalidParams, "invalid command: " & command & " (expected add or remove)")

  newJNull()

proc handleClearBanned(rpc: RpcServer): JsonNode =
  ## Clear all banned addresses
  if rpc.peerManager != nil:
    rpc.peerManager.clearBanned()
  newJNull()

proc handleDisconnectNode(rpc: RpcServer, params: JsonNode): JsonNode =
  ## disconnectnode "address" ( nodeid )
  ## Force disconnect a connected peer by address or nodeid.
  ## Reference: Bitcoin Core src/rpc/net.cpp::disconnectnode
  if params.len < 1 or params[0].getStr() == "":
    raise newRpcError(RpcInvalidParams, "missing address parameter")

  let node = params[0].getStr()

  if rpc.peerManager == nil:
    raise newRpcError(RpcInternalError, "peer manager not available")

  # Parse host:port
  var host = node
  var port = rpc.params.defaultPort
  let colonIdx = node.rfind(':')
  if colonIdx > 0:
    host = node[0 ..< colonIdx]
    try:
      port = uint16(parseInt(node[colonIdx + 1 .. ^1]))
    except ValueError:
      raise newRpcError(RpcInvalidParams, "invalid port number")

  var found = false
  for peer in rpc.peerManager.getReadyPeers():
    if peer.address == host and peer.port == port:
      asyncSpawn rpc.peerManager.removePeer(peer)
      found = true
      break

  if not found:
    # Core rpc/net.cpp::disconnectnode raises RPC_CLIENT_NODE_NOT_CONNECTED
    # (-29) with this exact message when CConnman::DisconnectNode matched no
    # connected peer (net.cpp:477-479) — not the generic JSON-RPC -32602.
    raise newRpcError(RpcClientNodeNotConnected, "Node not found in connected nodes")

  newJNull()

proc handleUptime(rpc: RpcServer): JsonNode =
  ## uptime
  ## Returns the total uptime of the server in seconds.
  ## Reference: Bitcoin Core src/rpc/server.cpp::uptime
  let now = getTime().toUnix()
  %int(now - rpc.startedAt)

proc handleGetMemoryInfo(rpc: RpcServer, params: JsonNode): JsonNode =
  ## getmemoryinfo ( "mode" )
  ## Returns an object containing information about memory usage.
  ##
  ## Reference: Bitcoin Core src/rpc/node.cpp getmemoryinfo (:145-198) +
  ## RPCLockedMemoryInfo (:113-124) + RPCMallocInfo (:126-143).
  ##
  ## IMPORTANT SEMANTICS: this RPC reports Core's SECURE LOCKED-MEMORY POOL
  ## (`LockedPoolManager` — the `mlock()`-backed allocator that keeps sensitive
  ## data such as wallet private keys OFF swap), NOT general process/heap memory.
  ## Do not confuse the "locked" memory here with the transaction "memory pool"
  ## (mempool).
  ##
  ## Param:
  ##   mode (str, OPTIONAL, default "stats"): kind of information to return.
  ##     - "stats":      general statistics about memory usage in the daemon.
  ##     - "mallocinfo": an XML string describing low-level heap state (Core:
  ##                     only available when compiled with glibc).
  ##
  ## Returns (mode-dependent, matching Core exactly):
  ##   - mode == "stats" -> OBJECT
  ##       { "locked": { "used": int, "free": int, "total": int,
  ##                     "locked": int, "chunks_used": int, "chunks_free": int } }
  ##     All six inner values are non-negative integers (Core `size_t`), in this
  ##     exact pushKV order. nimrod has NO Core-style `mlock()`-backed secure pool
  ##     (verified: no LockedPool / mlock / sodium_mlock / VirtualLock in the
  ##     source), so the honest answer is all zeros — but the keys/structure are
  ##     ALWAYS present and identical to Core. A node with an empty/absent locked
  ##     pool legitimately reports zeros; shape-match parity holds. We do NOT
  ##     fabricate nonzero values.
  ##   - mode == "mallocinfo" -> Core returns a glibc `malloc_info(3)` XML string
  ##     ONLY when built with glibc (HAVE_MALLOC_INFO); on every other build it
  ##     raises -8 "mallocinfo mode not available". nimrod has no glibc
  ##     `malloc_info` equivalent wired up, so we faithfully take Core's non-glibc
  ##     path — the exact -8 error — rather than fabricate a stub XML string Core
  ##     never emits.
  ##
  ## Errors:
  ##   - Non-string mode -> RPC_TYPE_ERROR (-3), a standard type check BEFORE any
  ##     handler logic (Core reads `mode` via `Arg<std::string_view>`).
  ##   - Unknown mode -> RPC_INVALID_PARAMETER (-8), message "unknown mode <mode>"
  ##     (Core node.cpp:194, `tfm::format("unknown mode %s", mode)`).
  ##
  ## Pure read-only introspection of the daemon's own memory accounting; no side
  ## effects, no chain/mempool/peer locks. Safe at any lifecycle stage.

  # mode is read by Core as Arg<std::string_view> — default "stats" when the
  # param is omitted or JNull; a non-string value is a JSON type error (-3)
  # before any handler logic runs.
  var mode = "stats"
  if params.len >= 1 and params[0].kind != JNull:
    if params[0].kind != JString:
      raise newRpcError(RpcTypeError,
        "JSON value of type " & $params[0].kind & " is not of expected type string")
    mode = params[0].getStr()

  if mode == "stats":
    # Core RPCLockedMemoryInfo() reads LockedPoolManager::Instance().stats() and
    # emits the six counters under "locked" in this exact order. nimrod has no
    # mlock'd secure allocator, so every counter is an honest 0. Keys are always
    # present.
    var locked = newJObject()
    locked["used"] = %0
    locked["free"] = %0
    locked["total"] = %0
    locked["locked"] = %0
    locked["chunks_used"] = %0
    locked["chunks_free"] = %0
    result = newJObject()
    result["locked"] = locked
    return result

  if mode == "mallocinfo":
    # Core returns glibc malloc_info(3) XML ONLY when built with glibc
    # (HAVE_MALLOC_INFO); otherwise it raises -8 "mallocinfo mode not available"
    # (node.cpp). nimrod takes Core's non-glibc path — the exact -8 error —
    # rather than fabricate a stub XML string Core never emits.
    raise newRpcError(RpcInvalidParameter, "mallocinfo mode not available")

  # Any other mode is Core's RPC_INVALID_PARAMETER (-8) "unknown mode %s".
  raise newRpcError(RpcInvalidParameter, "unknown mode " & mode)

proc handleLogging(rpc: RpcServer, params: JsonNode): JsonNode =
  ## logging ( ["include_category",...] ["exclude_category",...] )
  ## Gets and sets the debug-logging category configuration.
  ##
  ## Reference: Bitcoin Core src/rpc/node.cpp `logging` (:218-275) +
  ## `EnableOrDisableLogCategories` (:200-216); src/logging.cpp
  ## `LogCategoriesList` / `GetLogCategory` / `EnableCategory` /
  ## `DisableCategory`.
  ##
  ## CATEGORY SET: nimrod has a REAL category-based debug-logging system — the
  ## chronicles runtime topic registry (`chronicles/topics_registry`), gated
  ## per-record by topic state + active log level (the same mechanism `--debug=`
  ## drives at boot). The authoritative category NAME set is
  ## `ops.KnownDebugCategories` (fixed, mirrors Core's `LOG_CATEGORIES_BY_STR`).
  ## The names legitimately differ per node (Core has e.g. `kernel`/`txpackages`
  ## that nimrod lacks; nimrod adds `p2p`/`sync`/`peer`/`wallet`/`fees`/
  ## `consensus`) — only the SHAPE, param-semantics and the -8 error match Core.
  ##
  ## LIVE TOGGLE (no snapshot trap): this RPC mutates `ops`'s live active-set —
  ## `enableDebugCategory`/`disableDebugCategory` flip the chronicles topic state
  ## immediately, so a category enabled here makes its DEBUG logs actually start
  ## flowing with NO restart (Core's in-memory `m_categories` mutation). The
  ## returned map is rebuilt from the live set on every call, so it always
  ## reflects the just-applied change.
  ##
  ## Params (both OPTIONAL, positional, Core order: include THEN exclude):
  ##   include (array of category strings): categories to ENABLE.
  ##   exclude (array of category strings): categories to DISABLE.
  ## A param is acted on ONLY if it is an array (Core `request.params[i].isArray()`
  ## guard); null/omitted/missing is a no-op for that slot, so `logging` with no
  ## args is a pure read-and-report (no change). include is applied first, then
  ## exclude, so a category named in BOTH ends up DISABLED ("exclude wins").
  ##
  ## Special input-only tokens (never emitted as output keys): `"all"`/`"1"`/`""`
  ## expand to the full category mask; `"none"`/`"0"` clear it. In the include
  ## slot they enable/clear; in the exclude slot they disable the whole mask
  ## (Core's `GetLogCategory` maps ""/"1"/"all" -> ALL, and
  ## DisableCategory(ALL) clears every bit — `logging [], ["all"]` => all false).
  ##
  ## Returns: a JSON OBJECT mapping every category name in `KnownDebugCategories`
  ## -> bool (whether it is currently being debug logged), in ascending
  ## ALPHABETICAL key order (Core iterates a std::map; alphabetical order makes
  ## the output byte-stable). The all/1/none/0/"" tokens are never output keys.
  ##
  ## Errors:
  ##   Unknown category in EITHER array -> RPC_INVALID_PARAMETER (-8), message
  ##   "unknown logging category <cat>" (Core node.cpp:213). Thrown as soon as
  ##   the bad name is hit; include is scanned fully (in order) THEN exclude, and
  ##   any valid category BEFORE the bad one in the same call has ALREADY been
  ##   applied (partial application, no rollback — Core parity).
  ##   Non-string array element -> RPC_TYPE_ERROR (-3) (Core `get_str()`).
  ##
  ## Scope: mutates the running node's in-memory active set immediately; NOT
  ## persisted to config — resets on restart to the `--debug=` startup flags.
  ## Idempotent (enabling an already-on / disabling an already-off category
  ## still returns the full list).

  # Core special input-only tokens. ""/"1"/"all" -> whole mask (GetLogCategory).
  # "none"/"0" -> clear (nimrod parseDebugCategories parity; Core reaches the
  # same clear-all effect via DisableCategory of the ALL flag).
  proc applyCats(arr: JsonNode, enable: bool) =
    # Core EnableOrDisableLogCategories: only an ARRAY param is processed; the
    # caller already guards on isArray, but be defensive.
    if arr.isNil or arr.kind != JArray:
      return
    for item in arr:
      if item.kind != JString:
        # Core get_str() raises a JSON type error on a non-string element.
        raise newRpcError(RpcTypeError,
          "JSON value of type " & $item.kind & " is not of expected type string")
      let cat = item.getStr()
      if cat == "all" or cat == "1" or cat == "":
        if enable: opsMod.enableAllDebugCategories()
        else:      opsMod.disableAllDebugCategories()
        continue
      if cat == "none" or cat == "0":
        # Clear-all token (input-only). Same effect in either slot.
        opsMod.disableAllDebugCategories()
        continue
      if cat notin opsMod.KnownDebugCategories:
        # Core node.cpp:213 — EnableCategory/DisableCategory return false for an
        # unknown name -> -8 "unknown logging category <cat>". Partial-apply: the
        # valid categories scanned before this point are already applied.
        raise newRpcError(RpcInvalidParameter, "unknown logging category " & cat)
      if enable: opsMod.enableDebugCategory(cat)
      else:      opsMod.disableDebugCategory(cat)

  # Core order: include (params[0]) first, then exclude (params[1]); each acted
  # on only if it is an array (no-arg / null => report-only, no change).
  if params.len >= 1 and params[0].kind == JArray:
    applyCats(params[0], true)
  if params.len >= 2 and params[1].kind == JArray:
    applyCats(params[1], false)

  # Emit the full {category: active} map for every REAL category, alphabetically
  # sorted (Core std::map iteration order). Rebuilt from the LIVE active set so
  # it reflects the change just applied. all/1/none/0/"" are never keys.
  let active = opsMod.getActiveDebugCategories()
  var names: seq[string] = @[]
  for c in opsMod.KnownDebugCategories:
    names.add(c)
  names.sort()
  result = newJObject()
  for c in names:
    result[c] = %(c in active)

# Forward declaration: the getnetworkhashps estimator is defined later in this
# module (~line 13118), but getmininginfo (below) needs it to populate
# networkhashps. Core parity: getmininginfo emits
# getnetworkhashps().HandleRequest(request) (rpc/mining.cpp), not a hardcoded 0.
proc handleGetNetworkHashPS(rpc: RpcServer, params: JsonNode): JsonNode

proc handleGetMiningInfo(rpc: RpcServer): JsonNode =
  ## getmininginfo
  ## Returns a json object containing mining-related information.
  ## Reference: Bitcoin Core src/rpc/mining.cpp::getmininginfo
  ## W70d: was using targetToDifficulty (imprecise float path) and emitting
  ## targetHex as little-endian (toHex without reverseHex).  Now uses the W57
  ## helpers getDifficultyFromBits+difficultyJson and reverseHex(toHex(target))
  ## for byte-parity with Core.
  let height = rpc.chainState.bestHeight
  let bits = block:
    var b: uint32 = 0x1d00ffff'u32  # default genesis bits
    let blkOpt = rpc.chainState.db.getBlock(rpc.chainState.bestBlockHash)
    if blkOpt.isSome:
      b = blkOpt.get().header.bits
    b
  let target = bitsToTarget(bits)
  let diffNode = difficultyJson(getDifficultyFromBits(bits))
  # Compact bits as 8-char big-endian hex (Core format)
  let bitsHex = toHex(cast[array[4, byte]]([
    byte((bits shr 24) and 0xff),
    byte((bits shr 16) and 0xff),
    byte((bits shr 8) and 0xff),
    byte(bits and 0xff)
  ]))
  # target: big-endian 64-char hex (same as getblock/getblockheader)
  let targetHex = reverseHex(toHex(target))
  let chainName = case rpc.params.network
    of Mainnet:  "main"
    of Testnet3: "test"
    of Testnet4: "testnet4"
    of Regtest:  "regtest"
    of Signet:   "signet"
  # next block uses same bits as tip (accurate except at adjustment boundaries)
  let nextHeight = height + 1
  # Core getmininginfo (mining.cpp:465-477) does NOT emit `currentblocksize`.
  # blockmintxfee = ValueFromAmount(blockMinFeeRate.GetFeePerK()) with
  # DEFAULT_BLOCK_MIN_TX_FEE=1 sat/kvB → 0.00000001 BTC.
  var resp = newJObject()
  resp["blocks"]           = %height
  resp["currentblockweight"] = %0
  resp["currentblocktx"]  = %0
  resp["bits"]             = %bitsHex
  resp["difficulty"]       = diffNode
  resp["target"]           = %targetHex
  resp["networkhashps"]    = rpc.handleGetNetworkHashPS(newJArray())
  resp["pooledtx"]         = %rpc.mempool.count
  resp["blockmintxfee"]    = btcAmountNode(1)
  resp["chain"]            = %chainName
  var nextObj = newJObject()
  nextObj["height"]     = %nextHeight
  nextObj["bits"]       = %bitsHex
  nextObj["difficulty"] = diffNode
  nextObj["target"]     = %targetHex
  resp["next"]     = nextObj
  # Core v31.99 emits warnings as an ARRAY of strings (empty when no warnings),
  # not a bare string. Reference: mining.cpp GetWarnings (node/warnings).
  resp["warnings"] = newJArray()
  resp

proc handleGetTxOut(rpc: RpcServer, params: JsonNode): JsonNode =
  ## gettxout "txid" n ( include_mempool )
  ## Returns details about an unspent transaction output.
  ## Reference: Bitcoin Core src/rpc/blockchain.cpp::gettxout
  if params.len < 2:
    raise newRpcError(RpcInvalidParams, "gettxout requires txid and vout parameters")

  let txidHex = params[0].getStr()
  # Core ParseHashV (blockchain.cpp:1224, name "txid"): a malformed txid is
  # RPC_INVALID_PARAMETER (-8) before any UTXO lookup. A well-formed-but-absent
  # txid still returns JSON null below.
  validateHashV(txidHex, "txid")

  let voutNum = params[1].getInt()
  let includeMempool = if params.len >= 3: params[2].getBool() else: true

  # Parse txid (reverse display byte order → internal order)
  var txidBytes: array[32, byte]
  let reversed = reverseHex(txidHex)
  for i in 0 ..< 32:
    txidBytes[i] = byte(parseHexInt(reversed[i*2 .. i*2+1]))
  let txid = TxId(txidBytes)

  let isMainnet = rpc.params.network == Mainnet
  let isRegtest = rpc.params.network == Regtest

  # Check mempool first if requested
  if includeMempool:
    let entryOpt = rpc.mempool.get(txid)
    if entryOpt.isSome:
      let entry = entryOpt.get()
      if voutNum >= 0 and voutNum < entry.tx.outputs.len:
        let output = entry.tx.outputs[voutNum]
        return %*{
          "bestblock": reverseHex(toHex(array[32, byte](rpc.chainState.bestBlockHash))),
          "confirmations": 0,
          "value": btcAmountNode(int64(output.value)),
          "scriptPubKey": buildScriptPubKeyJson(output.scriptPubKey, isMainnet, isRegtest),
          "coinbase": false
        }

  # Look up in UTXO set
  let outpoint = OutPoint(txid: txid, vout: uint32(voutNum))
  let utxoOpt = rpc.chainState.getUtxo(outpoint)
  if utxoOpt.isNone:
    return newJNull()

  let utxo = utxoOpt.get()
  let confirmations = rpc.chainState.bestHeight - utxo.height + 1
  %*{
    "bestblock": reverseHex(toHex(array[32, byte](rpc.chainState.bestBlockHash))),
    "confirmations": confirmations,
    "value": btcAmountNode(int64(utxo.output.value)),
    "scriptPubKey": buildScriptPubKeyJson(utxo.output.scriptPubKey, isMainnet, isRegtest),
    "coinbase": utxo.isCoinbase
  }

proc handleHelp(rpc: RpcServer, params: JsonNode): JsonNode =
  ## help ( "command" )
  ## List all commands, or get help for a specified command.
  ## Reference: Bitcoin Core src/rpc/server.cpp::help
  let methods = @[
    "== Blockchain ==",
    "getbestblockhash",
    "getblock \"blockhash\" ( verbosity )",
    "getblockchaininfo",
    "getblockcount",
    "getblockfilter \"blockhash\" ( \"filtertype\" )",
    "getblockfrompeer \"blockhash\" peer_id",
    "getblockhash height",
    "getblockheader \"blockhash\" ( verbose )",
    "getblockstats hash_or_height ( stats )",
    "getchainstates",
    "getchaintips",
    "getchaintxstats ( nblocks \"blockhash\" )",
    "getdeploymentinfo ( \"blockhash\" )",
    "getdifficulty",
    "getsyncstate",
    "gettxout \"txid\" n ( include_mempool )",
    "gettxoutsetinfo ( \"hash_type\" )",
    "invalidateblock \"blockhash\"",
    "preciousblock \"blockhash\"",
    "pruneblockchain height",
    "reconsiderblock \"blockhash\"",
    "",
    "== Mining ==",
    "getblocktemplate ( template_request )",
    "getmininginfo",
    "submitblock \"hexdata\"",
    "",
    "== Mempool ==",
    "dumpmempool",
    "getmempoolancestors \"txid\" ( verbose )",
    "getmempooldescendants \"txid\" ( verbose )",
    "getmempoolentry \"txid\"",
    "getmempoolinfo",
    "getrawmempool ( verbose )",
    "loadmempool",
    "savemempool",
    "testmempoolaccept [\"rawtx\",...]",
    "",
    "== Network ==",
    "addnode \"node\" \"command\"",
    "clearbanned",
    "disconnectnode \"address\"",
    "getconnectioncount",
    "getnettotals",
    "getnetworkinfo",
    "getpeerinfo",
    "getzmqnotifications",
    "listbanned",
    "ping",
    "setban \"subnet\" \"command\" ( bantime absolute )",
    "setnetworkactive state",
    "",
    "== Rawtransactions ==",
    "createrawtransaction [{\"txid\":\"id\",\"vout\":n},...] [{\"address\":amount},{\"data\":\"hex\"},...] ( locktime replaceable )",
    "decoderawtransaction \"hexstring\"",
    "getrawtransaction \"txid\" ( verbose )",
    "sendrawtransaction \"hexstring\"",
    "submitpackage [\"rawtx\",...]",
    "",
    "== Util ==",
    "estimaterawfee conf_target ( threshold )",
    "estimatesmartfee conf_target ( \"estimate_mode\" )",
    "getindexinfo ( \"index_name\" )",
    "signmessage \"address\" \"message\"",
    "signmessagewithprivkey \"privkey\" \"message\"",
    "validateaddress \"address\"",
    "verifymessage \"address\" \"signature\" \"message\"",
    "",
    "== Wallet ==",
    "createwallet \"wallet_name\"",
    "fundrawtransaction \"hexstring\" ( options iswitness )",
    "getbalance",
    "getnewaddress",
    "getwalletinfo",
    "listunspent",
    "listtransactions ( count )",
    "loadwallet \"filename\"",
    "sendtoaddress \"address\" amount",
    "signrawtransactionwithwallet \"hexstring\" ( [{...},...] sighashtype )",
    "unloadwallet",
    "walletcreatefundedpsbt [{...}] [{addr:amt},...] ( locktime options bip32derivs )",
    "",
    "== Control ==",
    "getmemoryinfo ( \"mode\" )",
    "help ( \"command\" )",
    "logging ( [\"include_category\",...] [\"exclude_category\",...] )",
    "stop",
    "uptime",
    "",
    "== AssumeUTXO ==",
    "dumptxoutset \"path\"",
    "loadtxoutset \"path\"",
    "scrubunspendable",
  ]
  %methods.join("\n")

# Message signing / verification RPCs
# Reference: Bitcoin Core src/rpc/signmessage.cpp + src/wallet/rpc/signmessage.cpp
proc getTargetWallet(rpc: RpcServer): Wallet {.gcsafe.}

proc handleSignMessage(rpc: RpcServer, params: JsonNode): JsonNode =
  ## signmessage "address" "message"
  ## Sign a message with the private key of an address.
  ## Address must refer to a P2PKH key in a loaded wallet.
  ## Reference: bitcoin-core/src/wallet/rpc/signmessage.cpp signmessage
  if params.len < 2:
    raise newRpcError(RpcInvalidParams,
      "signmessage requires 2 parameters: address, message")

  let addrStr = params[0].getStr()
  let message = params[1].getStr()

  var parsedAddr: Address
  try:
    parsedAddr = decodeAddress(addrStr)
  except AddressError:
    raise newRpcError(RpcInvalidAddressOrKey, "Invalid address")

  if parsedAddr.kind != P2PKH:
    # Bitcoin Core uses RPC_TYPE_ERROR (-3) here. We don't have a constant
    # for that yet, but RpcInvalidAddressOrKey communicates the same intent
    # to clients that just check the message string.
    raise newRpcError(RpcInvalidAddressOrKey, "Address does not refer to key")

  let wallet = rpc.getTargetWallet()
  if wallet.isLocked:
    raise newRpcError(RpcMiscError,
      "Error: Please enter the wallet passphrase with walletpassphrase first.")

  let keyOpt = wallet.findKeyForAddress(parsedAddr)
  if keyOpt.isNone:
    raise newRpcError(RpcInvalidAddressOrKey,
      "Private key not available")

  let key = keyOpt.get()
  # nimrod-derived P2PKH addresses always use the compressed pubkey (see
  # wallet.derivePath BIP44 branch), so set the compressed flag accordingly.
  try:
    let signature = signMessage(key.extKey.key, message, compressed = true)
    return %signature
  except Secp256k1Error as e:
    raise newRpcError(RpcInvalidAddressOrKey, "Sign failed: " & e.msg)

proc handleVerifyMessage(rpc: RpcServer, params: JsonNode): JsonNode =
  ## verifymessage "address" "signature" "message"
  ## Verify a base64 ECDSA-recoverable signature against a P2PKH address.
  ## Reference: bitcoin-core/src/rpc/signmessage.cpp verifymessage
  if params.len < 3:
    raise newRpcError(RpcInvalidParams,
      "verifymessage requires 3 parameters: address, signature, message")

  let addrStr = params[0].getStr()
  let signature = params[1].getStr()
  let message = params[2].getStr()

  var parsedAddr: Address
  try:
    parsedAddr = decodeAddress(addrStr)
  except AddressError:
    raise newRpcError(RpcInvalidAddressOrKey, "Invalid address")

  if parsedAddr.kind != P2PKH:
    raise newRpcError(RpcInvalidAddressOrKey, "Address does not refer to key")

  let res = verifyMessageRaw(parsedAddr.pubkeyHash, signature, message)
  case res
  of mvrMalformedSignature:
    raise newRpcError(RpcInvalidAddressOrKey, "Malformed base64 encoding")
  of mvrInvalidAddress:
    raise newRpcError(RpcInvalidAddressOrKey, "Invalid address")
  of mvrAddressNoKey:
    raise newRpcError(RpcInvalidAddressOrKey, "Address does not refer to key")
  of mvrPubkeyNotRecovered, mvrNotSigned:
    return %false
  of mvrOk:
    return %true

proc handleSignMessageWithPrivkey(rpc: RpcServer, params: JsonNode): JsonNode =
  ## signmessagewithprivkey "privkey" "message"
  ## Sign a message with a given WIF-encoded private key (no wallet required).
  ## Reference: bitcoin-core/src/rpc/signmessage.cpp SignMessageWithPrivKey
  if params.len < 2:
    raise newRpcError(RpcInvalidParams,
      "signmessagewithprivkey requires 2 parameters: privkey, message")

  let wifStr = params[0].getStr()
  let message = params[1].getStr()

  var privKey: PrivateKey
  var compressed: bool
  try:
    let decoded = decodeWIF(wifStr)
    privKey = decoded.key
    compressed = decoded.compressed
  except DescriptorError as e:
    raise newRpcError(RpcInvalidAddressOrKey, "Invalid private key: " & e.msg)

  try:
    let signature = signMessage(privKey, message, compressed = compressed)
    return %signature
  except Secp256k1Error as e:
    raise newRpcError(RpcInvalidAddressOrKey, "Sign failed: " & e.msg)

proc handleValidateAddress(rpc: RpcServer, params: JsonNode): JsonNode =
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing address parameter")

  let addrStr = params[0].getStr()

  try:
    let parsedAddr = decodeAddress(addrStr)

    let scriptPubKey = scriptPubKeyForAddress(parsedAddr)
    let isWitness = parsedAddr.kind in {P2WPKH, P2WSH, P2TR}
    # Core: isscript=true for P2SH and any witness program >20 bytes (P2WSH=32B, P2TR=32B)
    let isScript = parsedAddr.kind in {P2SH, P2WSH, P2TR}

    # Core key order (rpc/output_script.cpp validateaddress +
    # rpc/util.cpp DescribeAddress):
    #   isvalid, address, scriptPubKey, isscript, iswitness,
    #   witness_version, witness_program.
    result = newJObject()
    result["isvalid"]      = %true
    result["address"]      = %addrStr
    result["scriptPubKey"] = %toHex(scriptPubKey)
    result["isscript"]     = %isScript
    result["iswitness"]    = %isWitness
    if isWitness:
      let witnessVer = if parsedAddr.kind == P2TR: 1 else: 0
      result["witness_version"]  = %witnessVer
      # witness_program: hex of the raw program bytes
      var prog: string
      case parsedAddr.kind
      of P2WPKH:
        prog = toHex(parsedAddr.wpkh)
      of P2WSH:
        prog = toHex(parsedAddr.wsh)
      of P2TR:
        prog = toHex(parsedAddr.taprootKey)
      else:
        prog = ""
      result["witness_program"]  = %prog
  except AddressError:
    # Core invalid-form key order: isvalid, error_locations, error.
    result = newJObject()
    result["isvalid"] = %false
    result["error_locations"] = newJArray()
    result["error"] = %"Invalid or unsupported Segwit (Bech32) or Base58 encoding."

# ============================================================================
# Pruning RPCs
# ============================================================================

proc handlePruneBlockchain(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Prune the blockchain up to a specified height
  ## Reference: Bitcoin Core rpc/blockchain.cpp pruneblockchain
  ##
  ## Arguments:
  ## 1. height (numeric, required) - The block height to prune up to
  ##                                   (or unix timestamp >= 1e9 — Core uses
  ##                                   GetBlockHashByTime in that case; we
  ##                                   reject for now to avoid surprising
  ##                                   semantics on a 4-year-history chain).
  ##
  ## Returns:
  ## The height of the last block pruned
  ##
  ## Note: Pruning requires -prune option to be enabled. Both auto-mode
  ## (--prune=N, N >= 550) and manual-mode (--prune=1) accept this RPC; only
  ## auto-mode runs the periodic background trigger.

  if rpc.pruner == nil or not rpc.pruner.isPruning:
    raise newRpcError(RpcMiscError,
      "Cannot prune blocks because node is not in prune mode.")

  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing height parameter")

  let targetHeight = params[0].getInt()
  let chainHeight = rpc.chainState.bestHeight

  if targetHeight < 0:
    raise newRpcError(RpcInvalidParams, "Negative block height.")

  # Bitcoin Core convention: a value >= 1_000_000_000 is interpreted as a
  # unix timestamp. We don't support that variant yet — be explicit so the
  # operator gets a useful error rather than silently pruning the genesis.
  if targetHeight >= 1_000_000_000:
    raise newRpcError(RpcInvalidParams,
      "Could not find block with at least the specified timestamp.")

  if targetHeight > chainHeight:
    raise newRpcError(RpcInvalidParams,
      "Blockchain is shorter than the attempted prune height.")

  # Core caps the requested height at tip - MIN_BLOCKS_TO_KEEP via a warning
  # log, but still allows the call (the FindFilesToPruneManual safety floor
  # short-circuits any over-aggressive request). We do the same — let the
  # pruner clamp internally.
  let newPruneHeight = rpc.pruner.pruneToHeight(int32(targetHeight))
  %newPruneHeight

# ============================================================================
# assumeUTXO / Snapshot RPCs
# ============================================================================

proc resolveRollbackTargetHeight(
    rpc: RpcServer, rollbackVal: JsonNode
): int32 =
  ## Resolve the `rollback` named-arg (height int or block-hash hex) to an
  ## active-chain height. Mirrors Core's ParseHashOrHeight.
  if rollbackVal.kind == JInt:
    let h = rollbackVal.getInt()
    if h < 0 or h > rpc.chainState.bestHeight.int:
      raise newRpcError(RpcInvalidParams,
        "Target block height " & $h & " is out of range")
    return int32(h)
  elif rollbackVal.kind == JString:
    let hashHex = rollbackVal.getStr()
    if hashHex.len != 64:
      raise newRpcError(RpcInvalidAddressOrKey, "Invalid block hash")
    let blockHash = parseBlockHash(hashHex)
    let idxOpt = rpc.chainState.db.getBlockIndex(blockHash)
    if idxOpt.isNone:
      raise newRpcError(RpcInvalidAddressOrKey, "Block not found")
    let idx = idxOpt.get()
    # Must be on the active chain.
    let activeAt = rpc.chainState.db.getBlockHashByHeight(idx.height)
    if activeAt.isNone or activeAt.get() != blockHash:
      raise newRpcError(RpcInvalidParams,
        "Block is not in the main chain")
    return idx.height
  else:
    raise newRpcError(RpcInvalidParams,
      "rollback must be a height (int) or block hash (string)")

proc handleDumpTxOutSet*(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Dump the UTXO set to a file
  ## Reference: Bitcoin Core rpc/blockchain.cpp dumptxoutset
  ##
  ## Arguments:
  ## 1. path (string, required) - Path to the output file
  ## 2. type (string, optional) - "" | "latest" | "rollback"
  ## 3. options (object, optional) - { "rollback": <height|hash> }
  ##
  ## When "rollback" is selected (with or without an explicit height/hash),
  ## the node temporarily disconnects blocks from the tip back to the target,
  ## writes the snapshot, then re-applies the saved blocks back to the
  ## original tip. Mirrors Bitcoin Core's TemporaryRollback dance in
  ## rpc/blockchain.cpp::dumptxoutset.
  ##
  ## Returns:
  ## {
  ##   "coins_written": n,
  ##   "base_hash": "...",
  ##   "base_height": n,
  ##   "path": "...",
  ##   "txoutset_hash": "...",
  ##   "nchaintx": n            (only when target matches an assumeutxo entry)
  ## }

  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing path parameter")

  let path = params[0].getStr()
  if path == "":
    raise newRpcError(RpcInvalidParams, "path cannot be empty")

  # Refuse to overwrite an existing file (matches Core's "path already exists").
  if fileExists(path):
    raise newRpcError(RpcMiscError, "path already exists: " & path)

  # Parse arg 2 (type) and arg 3 (options{rollback}). All optional.
  let snapshotType =
    if params.len >= 2 and params[1].kind == JString: params[1].getStr()
    else: ""
  let optionsObj =
    if params.len >= 3 and params[2].kind == JObject: params[2]
    else: newJObject()

  let originalTipHeight = rpc.chainState.bestHeight
  var targetHeight: int32 = originalTipHeight

  if optionsObj.hasKey("rollback"):
    if snapshotType.len > 0 and snapshotType != "rollback":
      raise newRpcError(RpcInvalidParams,
        "Invalid snapshot type \"" & snapshotType &
        "\" specified with rollback option")
    targetHeight = resolveRollbackTargetHeight(rpc, optionsObj["rollback"])
  elif snapshotType == "rollback":
    # Pick the highest assumeutxo entry <= current tip.
    var best: int32 = -1
    for entry in rpc.chainState.params.assumeutxoData:
      if entry.height <= originalTipHeight and entry.height > best:
        best = entry.height
    if best < 0:
      raise newRpcError(RpcMiscError,
        "No assumeutxo snapshot entry available at or below current tip " &
        $originalTipHeight)
    targetHeight = best
  elif snapshotType == "latest" or snapshotType == "":
    targetHeight = originalTipHeight
  else:
    raise newRpcError(RpcInvalidParams,
      "Invalid snapshot type \"" & snapshotType &
      "\" specified. Please specify \"rollback\" or \"latest\"")

  if targetHeight > originalTipHeight:
    raise newRpcError(RpcInvalidParams,
      "Target height above current tip")

  # Pruned-mode pre-check. Mirrors Bitcoin Core
  # rpc/blockchain.cpp:dumptxoutset:
  #     if (IsPruneMode() &&
  #         target_index->nHeight < node.chainman->m_blockman.GetFirstBlock()->nHeight)
  #         throw "Block height N not available (pruned data). Use a height after M.";
  # We fail fast here so a pruned datadir does not begin a rewind that is
  # guaranteed to fail when disconnectBlock reads pruned undo data.
  if rpc.blockFileManager != nil and rpc.blockFileManager.isPruneMode():
    let firstAvailable = rpc.blockFileManager.getPruneHeight()
    if firstAvailable >= 0 and targetHeight < firstAvailable:
      raise newRpcError(RpcMiscError,
        "Block height " & $targetHeight &
        " not available (pruned data). Use a height after " &
        $(firstAvailable - 1) & ".")

  # NetworkDisable RAII (Nim try/finally). Mirrors Bitcoin Core's
  # NetworkDisable wrapper around TemporaryRollback in
  # rpc/blockchain.cpp::dumptxoutset. Pause inbound block acceptance for
  # the duration of the rewind→dump→replay dance; restore on every exit
  # path (success, error, exception) so peers can resume submitting once
  # the original tip is back. Only active when there's actual rewind work.
  let networkPauseActive = targetHeight < originalTipHeight
  if networkPauseActive:
    rpc.blockSubmissionPaused = true
  defer:
    if networkPauseActive:
      rpc.blockSubmissionPaused = false

  # Walk the active chain from the current tip down to (but not including)
  # targetHeight, collecting full Block payloads in disconnect order. We need
  # to capture these BEFORE disconnect since disconnectBlock removes the
  # height->hash mapping (chainstate.nim:949).
  var disconnectOrder: seq[(BlockHash, int32, Block)] = @[]
  if targetHeight < originalTipHeight:
    var h = originalTipHeight
    while h > targetHeight:
      let hashOpt = rpc.chainState.db.getBlockHashByHeight(h)
      if hashOpt.isNone:
        raise newRpcError(RpcInternalError,
          "no block at height " & $h & " during rollback collection")
      let blkOpt = rpc.chainState.db.getBlock(hashOpt.get())
      if blkOpt.isNone:
        raise newRpcError(RpcInternalError,
          "missing block data for " & $hashOpt.get() &
          " — pruned datadir cannot rollback")
      disconnectOrder.add((hashOpt.get(), h, blkOpt.get()))
      dec h

  # Re-apply order is reverse of disconnect order (low height first).
  proc reapplyAll(rpc: RpcServer,
                  ordered: seq[(BlockHash, int32, Block)]): bool =
    for i in countdown(ordered.high, 0):
      let (_, height, blk) = ordered[i]
      let cr = rpc.chainState.connectBlock(blk, height)
      if not cr.isOk:
        error "dumptxoutset: failed to re-apply block during rollback recovery",
          height = height, error = cr.error
        return false
    true

  # Disconnect down to targetHeight. Track how far we got so partial failure
  # can be reverted.
  var disconnectedCount = 0
  for i in 0 ..< disconnectOrder.len:
    let (_, h, blk) = disconnectOrder[i]
    let dr = rpc.chainState.disconnectBlock(blk)
    if not dr.isOk:
      # Best-effort: re-apply what we already disconnected.
      let already = disconnectOrder[0 ..< disconnectedCount]
      discard reapplyAll(rpc, already)
      raise newRpcError(RpcMiscError,
        "rollback disconnect failed at height " & $h & ": " & dr.error)
    inc disconnectedCount

  if rpc.chainState.bestHeight != targetHeight:
    # Try to recover before bailing out.
    discard reapplyAll(rpc, disconnectOrder)
    raise newRpcError(RpcMiscError,
      "Could not roll back to requested height: ended at " &
      $rpc.chainState.bestHeight & ", wanted " & $targetHeight)

  # Write the snapshot at the rolled-back state.
  var dumpRes: tuple[coinsWritten: uint64, baseHash: BlockHash,
                     baseHeight: int32, txoutsetHash: array[32, byte]]
  var dumpErr = ""
  try:
    dumpRes = createSnapshot(rpc.chainState, path, rpc.chainState.params)
  except SnapshotError as e:
    dumpErr = "snapshot write failed: " & e.msg
  except IOError as e:
    dumpErr = "snapshot I/O error: " & e.msg

  # Always attempt to re-apply blocks back to the original tip.
  let reapplyOk = reapplyAll(rpc, disconnectOrder)

  if dumpErr.len > 0:
    raise newRpcError(RpcInternalError, dumpErr)
  if not reapplyOk:
    # Snapshot was written but we couldn't restore the chain. Surface that.
    raise newRpcError(RpcInternalError,
      "snapshot written to " & path &
      " but failed to re-apply rolled-back blocks; chainstate at height " &
      $rpc.chainState.bestHeight & " (was " & $originalTipHeight & ")")

  # If the dump base height matches a known assumeutxo entry, surface
  # nchaintx (Core does the same).
  var nchaintx: uint64 = 0
  var haveNChainTx = false
  for entry in rpc.chainState.params.assumeutxoData:
    if entry.height == dumpRes.baseHeight and
       entry.blockhash == dumpRes.baseHash:
      nchaintx = entry.chainTxCount
      haveNChainTx = true
      break

  result = %*{
    "coins_written": dumpRes.coinsWritten,
    "base_hash": reverseHex(toHex(array[32, byte](dumpRes.baseHash))),
    "base_height": dumpRes.baseHeight,
    "path": path,
    "txoutset_hash": reverseHex(toHex(dumpRes.txoutsetHash))
  }
  if haveNChainTx:
    result["nchaintx"] = %nchaintx

proc handleLoadTxOutSetImpl*(rpc: RpcServer, path: string): JsonNode =
  ## REAL loadtxoutset: after the load-time content-hash gate (which
  ## authenticates the snapshot file), spin up the SECOND background
  ## chainstate (own coins store), connect genesis->base, and compare the
  ## independently-recomputed HASH_SERIALIZED to the assumeUTXO commitment.
  ##
  ## Mirrors Bitcoin Core's `loadtxoutset` (rpc/blockchain.cpp) +
  ## `ChainstateManager::ActivateSnapshot`/`AddChainstate`/`MaybeValidateSnapshot`
  ## (validation.cpp:5588/6170/5967), and the camlcoin/blockbrew/hotbuns/lunarblock
  ## pilots. A snapshot is loaded into an ISOLATED store (a sibling
  ## `<chainstate>-snapshot` dir) so a refused/invalid load NEVER pollutes the
  ## live chainstate. The verdict is surfaced via `getchainstates`
  ## (validated=false while bg runs / after a mismatch, true after a match) —
  ## Core's async `AbortNode` model means `loadtxoutset` itself returns Ok and
  ## a mismatch is reported out-of-band rather than as an RPC error.

  let assumeData = rpc.effectiveAssumeutxoData()

  # Derive isolated store directories siblings to the active chainstate.
  # `undoMgr.dataDir` is `<dbPath>/blocks`, so parentDir is the active store dir.
  let activeDir = rpc.chainState.undoMgr.dataDir.parentDir
  let snapDir = activeDir & "-snapshot"
  let bgDir = activeDir & "-bgvalidate"
  for d in [snapDir, bgDir]:
    try:
      if dirExists(d): removeDir(d)
      createDir(d)
    except OSError as e:
      raise newRpcError(RpcInternalError, "failed to prepare snapshot dir: " & e.msg)

  # 1) Load the snapshot into its OWN isolated ChainState (NOT rpc.chainState).
  #    loadSnapshot runs the load-time HASH_SERIALIZED gate; a bad file is
  #    refused here, before any background work, leaving the live state intact.
  var snapCs = newChainState(snapDir, rpc.params)
  let load = loadSnapshot(path, snapCs, rpc.params, assumeData)
  if not load.success:
    snapCs.close()
    try: removeDir(snapDir) except OSError: discard
    try: removeDir(bgDir) except OSError: discard
    # Core returns RPC_INTERNAL_ERROR when ActivateSnapshot cannot proceed.
    raise newRpcError(RpcInternalError, "Unable to load UTXO snapshot: " & load.error)

  let snapshotCs = newSnapshotChainState(snapCs)
  snapshotCs.assumeutxo = auUnvalidated
  snapshotCs.role = csrSnapshot
  snapshotCs.snapshotBlockhash = some(snapCs.bestBlockHash)
  # Resolve the assumed hash + base height from the matched whitelist entry.
  var assumedHash: array[32, byte]
  var baseHeight: int32 = snapCs.bestHeight
  for d in assumeData:
    if d.blockhash == snapCs.bestBlockHash:
      assumedHash = d.hashSerialized
      baseHeight = d.height
      break
  snapshotCs.targetUtxoHash = some(assumedHash)

  # 2) Build the SECOND background chainstate (own store) + drive genesis->base.
  let activation = activateSnapshotWithBackground(
    snapshotCs, bgDir, assumedHash, baseHeight)
  rpc.snapshotActivation = activation

  # Block source for the background re-connection: the active chainstate's
  # persisted block bodies (genesis->base are already on disk from IBD).
  let activeChain = rpc.chainState
  proc getBlockByHeight(h: int32): Option[Block] {.gcsafe, raises: [].} =
    {.gcsafe.}:
      try:
        let hashOpt = activeChain.db.getBlockHashByHeight(h)
        if hashOpt.isNone:
          return none(Block)
        return activeChain.db.getBlock(hashOpt.get())
      except CatchableError:
        return none(Block)

  # 3) Run the background validation synchronously (small regtest chains) and
  #    record the verdict on snapshotCs.assumeutxo (read by getchainstates).
  let verdict = runSnapshotValidation(activation, getBlockByHeight)

  # Core async AbortNode model: loadtxoutset returns Ok regardless; a mismatch
  # is surfaced through getchainstates validated=false. We log the verdict.
  let baseHashHex = reverseHex(toHex(array[32, byte](snapCs.bestBlockHash)))
  result = %*{
    "coins_loaded": load.coinsLoaded,
    "tip_hash": baseHashHex,
    "base_height": baseHeight,
    "path": path
  }
  if verdict.validated:
    result["validated"] = %true
  else:
    result["validated"] = %false
    result["validation_error"] = %verdict.error

proc handleLoadTxOutSet*(rpc: RpcServer, params: JsonNode): JsonNode =
  ## `loadtxoutset "path"` — load a Core-format UTXO snapshot and drive the
  ## real background dual-chainstate validation (see `handleLoadTxOutSetImpl`).
  ## Mirrors `bitcoin-core/src/rpc/blockchain.cpp::loadtxoutset`. The load-time
  ## content-hash gate authenticates the file; a second background chainstate
  ## then re-connects genesis->base in its OWN coins store and recomputes the
  ## HASH_SERIALIZED to trustlessly re-verify the snapshot. The verdict is
  ## reported via `getchainstates` (validated). A snapshot whose base blockhash
  ## is not in the assumeUTXO whitelist is refused with RPC_INTERNAL_ERROR.
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing path parameter")
  let path = params[0].getStr()
  if path == "":
    raise newRpcError(RpcInvalidParams, "path cannot be empty")
  rpc.handleLoadTxOutSetImpl(path)

proc formatBtcAmount(satoshi: int64): string =
  ## Format a satoshi amount as Core's `ValueFromAmount` does:
  ## `<sign><quotient>.<8-digit-remainder>`. JSON treats this as a number.
  ## Reference: bitcoin-core/src/core_io.cpp::ValueFromAmount.
  let neg = satoshi < 0
  let abs = if neg: -satoshi else: satoshi
  let q = abs div 100_000_000'i64
  let r = abs mod 100_000_000'i64
  var rStr = $r
  while rStr.len < 8:
    rStr = "0" & rStr
  (if neg: "-" else: "") & $q & "." & rStr

proc handleGetTxOutSetInfo*(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Return statistics about the UTXO set.
  ##
  ## Reference: bitcoin-core/src/rpc/blockchain.cpp::gettxoutsetinfo,
  ## bitcoin-core/src/kernel/coinstats.cpp::ComputeUTXOStats.
  ##
  ## Arguments:
  ## 1. hash_type (string, optional, default="hash_serialized_3") -
  ##    "hash_serialized_3" (alias "hash_serialized_2", "hash_serialized"),
  ##    "muhash", or "none".
  ##
  ## Returns:
  ## {
  ##   "height":             (numeric) chain tip height
  ##   "bestblock":          (string)  display-byte-order tip hash
  ##   "transactions":       (numeric) distinct UTXO-bearing txids
  ##   "txouts":             (numeric) total UTXO count
  ##   "bogosize":           (numeric) Core's database-independent size estimate
  ##   "hash_serialized_3":  (string)  SHA256d hash of UTXO set (HASH_SERIALIZED only)
  ##   "hash_serialized_2":  (string)  alias for hash_serialized_3 (cross-impl harness compat)
  ##   "muhash":             (string)  MuHash3072 finalize digest (MUHASH only)
  ##   "total_amount":       (numeric) sum of all UTXO values, in BTC
  ## }
  let hashTypeStr = if params.len >= 1 and params[0].kind == JString:
                      params[0].getStr()
                    else:
                      "hash_serialized_3"

  let coinHashType = case hashTypeStr
    of "hash_serialized_3", "hash_serialized_2", "hash_serialized":
      cshtHashSerialized
    of "muhash":
      cshtMuHash
    of "none":
      cshtNone
    else:
      # Core's `ParseHashType` rejects an unrecognised hash_type with
      # RPC_INVALID_PARAMETER (-8) and this exact message
      # (bitcoin-core/src/rpc/blockchain.cpp:976). Match the code AND the
      # phrasing so the differential harness sees like-for-like.
      raise newRpcError(RpcInvalidParameter,
                        "'" & hashTypeStr & "' is not a valid hash_type")

  # hash_or_height (params[1]) targets a SPECIFIC block.  Core only supports
  # this with -coinstatsindex; the index FIRST guards a non-tip query and
  # throws RPC_INVALID_PARAMETER (-8) "Querying specific block heights requires
  # coinstatsindex" when the index is disabled (blockchain.cpp:1085-1097),
  # BEFORE the hash_serialized_3-specific guard.  We mirror that exactly:
  #   * index OFF  -> -8 (unchanged from before).
  #   * index ON   -> serve the per-height snapshot from the coinstatsindex
  #                   for MUHASH / NONE; hash_serialized_3 at a specific height
  #                   is STILL rejected -8 (Core: blockchain.cpp:1089-1091
  #                   "hash_serialized_3 hash type cannot be queried for a
  #                   specific block") — the index serves muhash only.
  if params.len >= 2 and params[1].kind != JNull:
    if rpc.coinStatsIndex == nil or not rpc.coinStatsIndex.enabled:
      raise newRpcError(RpcInvalidParameter,
                        "Querying specific block heights requires coinstatsindex")

    # hash_serialized_3 cannot be recomputed from the index at an arbitrary
    # height (it is a chainstate-only hash, valid only at the tip).
    if coinHashType == cshtHashSerialized:
      raise newRpcError(RpcInvalidParameter,
        "hash_serialized_3 hash type cannot be queried for a specific block")

    # Resolve hash_or_height -> a block height present in the active chain.
    var targetHeight: int32
    case params[1].kind
    of JInt:
      let hOrH = params[1].getInt()
      # Core's ParseHashOrHeight treats a small integer as a height and a
      # 64-hex string as a block hash.  Bounds-check the height.
      if hOrH < 0 or hOrH > int(rpc.chainState.bestHeight):
        raise newRpcError(RpcInvalidParameter,
                          "Target block height " & $hOrH & " after current tip " &
                          $rpc.chainState.bestHeight)
      targetHeight = int32(hOrH)
    of JString:
      let blockHash = parseBlockHash(params[1].getStr())
      let idxOpt = rpc.chainState.db.getBlockIndex(blockHash)
      if idxOpt.isNone:
        raise newRpcError(RpcInvalidAddressOrKey, "Block not found")
      let bidx = idxOpt.get()
      # Must be on the active chain (Core resolves via the active ChainstateManager).
      let atHeight = rpc.chainState.db.getBlockHashByHeight(bidx.height)
      if atHeight.isNone or atHeight.get() != bidx.hash:
        raise newRpcError(RpcInvalidParameter, "Block is not in main chain")
      targetHeight = bidx.height
    else:
      raise newRpcError(RpcInvalidParameter,
                        "hash_or_height must be a height (int) or block hash (string)")

    # Pull the per-height snapshot the index folded forward on connect.
    let statsOpt = rpc.coinStatsIndex.getStats(targetHeight)
    if statsOpt.isNone:
      # The index is enabled but has not (yet) indexed this height.  Mirror
      # Core's "still syncing" path with an internal error rather than a -8.
      raise newRpcError(RpcInternalError,
        "Unable to get data because coinstatsindex is still syncing. " &
        "Current height: " & $rpc.coinStatsIndex.bestIndexedHeight())
    let stats = statsOpt.get()

    # Build the index-path response shape (blockchain.cpp:1112-1173).  When the
    # index is used, Core OMITS `transactions` + `disk_size` and ADDS
    # `total_unspendable_amount` + `block_info`.
    var resp = %*{
      "height": stats.height,
      "bestblock": reverseHex(toHex(array[32, byte](stats.blockHash))),
      "txouts": stats.transactionOutputCount,
      "bogosize": stats.bogoSize
    }
    if coinHashType == cshtMuHash:
      resp["muhash"] = %reverseHex(toHex(stats.muhash))
    resp["total_amount"] = parseJson(formatBtcAmount(stats.totalAmount))

    let blockTotalUnspendable = stats.totalUnspendablesGenesisBlock +
                                stats.totalUnspendablesBip30 +
                                stats.totalUnspendablesScripts +
                                stats.totalUnspendablesUnclaimedRewards
    resp["total_unspendable_amount"] =
      parseJson(formatBtcAmount(blockTotalUnspendable))

    # Per-block deltas vs the parent height's snapshot (block_info).  Zeroes at
    # height 0 (no parent).  The harness does not gate block_info, but we emit
    # it for Core-shape parity.
    var prevPrevoutSpent: uint64 = 0
    var prevCoinbase: uint64 = 0
    var prevNewOutputs: uint64 = 0
    var prevUnspendableGenesis: int64 = 0
    var prevUnspendableBip30: int64 = 0
    var prevUnspendableScripts: int64 = 0
    var prevUnspendableUnclaimed: int64 = 0
    if stats.height > 0:
      let prevOpt = rpc.coinStatsIndex.getStats(stats.height - 1)
      if prevOpt.isSome:
        let prev = prevOpt.get()
        prevPrevoutSpent = prev.totalPrevoutSpentAmount
        prevCoinbase = prev.totalCoinbaseAmount
        prevNewOutputs = prev.totalNewOutputsExCoinbase
        prevUnspendableGenesis = prev.totalUnspendablesGenesisBlock
        prevUnspendableBip30 = prev.totalUnspendablesBip30
        prevUnspendableScripts = prev.totalUnspendablesScripts
        prevUnspendableUnclaimed = prev.totalUnspendablesUnclaimedRewards

    let prevBlockTotalUnspendable = prevUnspendableGenesis + prevUnspendableBip30 +
                                    prevUnspendableScripts + prevUnspendableUnclaimed
    var blockInfo = %*{
      "prevout_spent": parseJson(formatBtcAmount(
        int64(stats.totalPrevoutSpentAmount - prevPrevoutSpent))),
      "coinbase": parseJson(formatBtcAmount(
        int64(stats.totalCoinbaseAmount - prevCoinbase))),
      "new_outputs_ex_coinbase": parseJson(formatBtcAmount(
        int64(stats.totalNewOutputsExCoinbase - prevNewOutputs))),
      "unspendable": parseJson(formatBtcAmount(
        blockTotalUnspendable - prevBlockTotalUnspendable))
    }
    blockInfo["unspendables"] = %*{
      "genesis_block": parseJson(formatBtcAmount(
        stats.totalUnspendablesGenesisBlock - prevUnspendableGenesis)),
      "bip30": parseJson(formatBtcAmount(
        stats.totalUnspendablesBip30 - prevUnspendableBip30)),
      "scripts": parseJson(formatBtcAmount(
        stats.totalUnspendablesScripts - prevUnspendableScripts)),
      "unclaimed_rewards": parseJson(formatBtcAmount(
        stats.totalUnspendablesUnclaimedRewards - prevUnspendableUnclaimed))
    }
    resp["block_info"] = blockInfo
    return resp

  let info = computeUtxoSetInfo(rpc.chainState, coinHashType)

  # Core none/tip-path key order (blockchain.cpp:1114-1130):
  #   height, bestblock, txouts, bogosize, [hash_serialized_3 | muhash],
  #   total_amount, transactions, disk_size.
  var response = %*{
    "height": info.height,
    "bestblock": reverseHex(toHex(array[32, byte](info.bestBlock))),
    "txouts": info.txOuts,
    "bogosize": info.bogosize
  }

  case coinHashType
  of cshtHashSerialized:
    # Emit BOTH `_3` (Core's current key) and `_2` (legacy alias the
    # cross-impl diff-test prefers). Display byte-order via reverseHex,
    # mirroring Core's `stats.hashSerialized.GetHex()` (uint256::GetHex
    # reverses internally).
    let hexStr = reverseHex(toHex(info.hashSerialized))
    response["hash_serialized_3"] = %hexStr
    response["hash_serialized_2"] = %hexStr
  of cshtMuHash:
    response["muhash"] = %reverseHex(toHex(info.hashSerialized))
  of cshtNone: discard

  response["total_amount"] = parseJson(formatBtcAmount(info.totalAmount))
  response["transactions"] = %info.transactions
  # `disk_size`: Core emits this (alongside `transactions`) whenever the
  # coinstatsindex is NOT used — see blockchain.cpp:1127-1129. It is the
  # estimated chainstate-on-disk size via CCoinsViewDB::EstimateSize(), which
  # returns 0 while the coins are still in the in-memory cache (unflushed
  # regtest chainstate). The value is impl-specific / non-load-bearing per the
  # RPC contract, so the cross-impl agreement (rustoshi, blockbrew, clearbit) is
  # to emit the literal 0 on the unflushed-regtest non-index path rather than
  # the live computed cfUtxo byte sum. The coinstatsindex path (above) OMITS
  # disk_size entirely and must stay that way.
  response["disk_size"] = %(0'u64)

  response

proc parseScanObject(rpc: RpcServer, scanobject: JsonNode): seq[byte] =
  ## Translate a single scanobject into the scriptPubKey bytes to match.
  ##
  ## Supported (minimal, mirrors the simplest descriptors Core accepts in
  ## scantxoutset — see bitcoin-core/src/rpc/blockchain.cpp::scantxoutset →
  ## EvalDescriptorStringOrObject):
  ##   addr(<address>)        — outputs paying to <address>'s scriptPubKey
  ##   raw(<scriptPubKey-hex>) — outputs whose script equals these exact bytes
  ##
  ## Core also accepts an object form { "desc": "...", "range": ... }; we
  ## accept the object's "desc" string but ignore "range" (xpub-range
  ## descriptors are out of scope). Single-key pkh()/wpkh()/tr() descriptors
  ## and combo() are NOT yet supported (follow-up).
  var desc: string
  case scanobject.kind
  of JString:
    desc = scanobject.getStr()
  of JObject:
    if not scanobject.hasKey("desc") or scanobject["desc"].kind != JString:
      raise newRpcError(RpcInvalidParams,
                        "Scan object needs to be either a string or an object")
    desc = scanobject["desc"].getStr()
  else:
    raise newRpcError(RpcInvalidParams,
                      "Scan object needs to be either a string or an object")

  # Strip an optional BIP-380 checksum suffix (#xxxxxxxx); we don't verify it.
  let hashPos = desc.find('#')
  if hashPos >= 0:
    desc = desc[0 ..< hashPos]
  desc = desc.strip()

  if desc.startsWith("addr(") and desc.endsWith(")"):
    let addrStr = desc[5 ..< desc.len - 1].strip()
    try:
      let parsedAddr = decodeAddress(addrStr)
      return scriptPubKeyForAddress(parsedAddr)
    except AddressError as e:
      raise newRpcError(RpcInvalidAddressOrKey,
                        "Address is not valid: " & addrStr & " (" & e.msg & ")")
  elif desc.startsWith("raw(") and desc.endsWith(")"):
    let hexStr = desc[4 ..< desc.len - 1].strip()
    if hexStr.len mod 2 != 0:
      raise newRpcError(RpcInvalidParams, "raw() script is not hex")
    for c in hexStr:
      if c notin HexDigits:
        raise newRpcError(RpcInvalidParams, "raw() script is not hex")
    return hexToBytes(hexStr)
  else:
    raise newRpcError(RpcInvalidParams,
                      "Unsupported descriptor '" & desc &
                      "'; scantxoutset supports addr(<address>) and " &
                      "raw(<hex>) only")

proc handleScanTxOutSet*(rpc: RpcServer, params: JsonNode): JsonNode =
  ## scantxoutset "action" [ scanobjects ]
  ##
  ## Scans the current UTXO set for outputs whose scriptPubKey matches any of
  ## the supplied scan objects, and returns the matches plus set-wide stats.
  ##
  ## Reference: bitcoin-core/src/rpc/blockchain.cpp::scantxoutset.
  ##
  ## Supported actions:
  ##   "start"  — run the scan (only this does real work; scanobjects required)
  ##   "status" — no persistent scan state here; returns null (no scan running)
  ##   "abort"  — no scan to abort here; returns false
  ##
  ## Supported scan objects (minimal): addr(<address>), raw(<hex>). See
  ## parseScanObject. Single-key descriptors / xpub ranges are out of scope.
  ##
  ## Returns (action=="start"):
  ## {
  ##   "success":      true,
  ##   "txouts":       total UTXOs scanned,
  ##   "height":       chain tip height,
  ##   "bestblock":    tip hash (display byte order),
  ##   "unspents":     [ {txid,vout,scriptPubKey,desc,amount,coinbase,
  ##                       height,blockhash,confirmations} ... ],
  ##   "total_amount": sum of matched amounts, in BTC
  ## }
  if params.len < 1 or params[0].kind != JString:
    raise newRpcError(RpcInvalidParams, "action argument is required")

  let action = params[0].getStr()

  if action == "status":
    # No long-running background scan in this implementation, so there is
    # never a scan in progress — Core returns null in that case.
    return newJNull()
  elif action == "abort":
    # Nothing to abort (no scan in progress) — Core returns false.
    return %false
  elif action != "start":
    raise newRpcError(RpcInvalidParams, "Invalid action '" & action & "'")

  # action == "start"
  if params.len < 2 or params[1].kind != JArray:
    raise newRpcError(RpcMiscError,
                      "scanobjects argument is required for the start action")

  # Build the set of scriptPubKey "needles" to match against.
  var needles = initHashSet[seq[byte]]()
  for scanobject in params[1]:
    needles.incl(rpc.parseScanObject(scanobject))

  let isMainnet = rpc.params.network == Mainnet

  # Snapshot tip BEFORE the walk; iterateUtxos flushes state to disk so the
  # cursor sees the authoritative set (mirrors Core's ForceFlushStateToDisk).
  let tipHeight = rpc.chainState.bestHeight
  let tipHash = rpc.chainState.bestBlockHash

  var count: int64 = 0
  var totalIn: int64 = 0
  let unspents = newJArray()

  for (outpoint, entry) in rpc.chainState.iterateUtxos():
    inc count  # total UTXOs scanned, matched or not

    if entry.output.scriptPubKey notin needles:
      continue

    let amount = int64(entry.output.value)
    totalIn += amount

    # Canonical hash of the active-chain block at the coin's height
    # (Core: tip->GetAncestor(coin.nHeight)->GetBlockHash().GetHex()).
    let blockHashOpt = rpc.chainState.getBlockHashByHeight(entry.height)
    let blockHashHex =
      if blockHashOpt.isSome:
        reverseHex(toHex(array[32, byte](blockHashOpt.get())))
      else:
        ""

    let unspent = %*{
      "txid": reverseHex(toHex(array[32, byte](outpoint.txid))),
      "vout": outpoint.vout,
      "scriptPubKey": toHex(entry.output.scriptPubKey),
      "desc": inferAddrDescriptor(entry.output.scriptPubKey, isMainnet),
      "amount": btcAmountNode(amount),
      "coinbase": entry.isCoinbase,
      "height": entry.height,
      "blockhash": blockHashHex,
      "confirmations": tipHeight - entry.height + 1
    }
    unspents.add(unspent)

  result = %*{
    "success": true,
    "txouts": count,
    "height": tipHeight,
    "bestblock": reverseHex(toHex(array[32, byte](tipHash))),
    "unspents": unspents,
    "total_amount": btcAmountNode(totalIn)
  }

proc handleScanBlocks*(rpc: RpcServer, params: JsonNode): JsonNode =
  ## scanblocks "action" ( [scanobjects] start_height stop_height "filtertype"
  ##                        options )
  ##
  ## Drive the BIP-157 basic block filter index to return every block whose
  ## GCS filter MATCHES any of the supplied scanobjects' scriptPubKeys over
  ## [start_height, stop_height].  It is the index-side counterpart to
  ## scantxoutset (which walks the UTXO set): scanblocks walks compact block
  ## filters, so it can locate the block a script was funded/spent in even
  ## after the coin is gone.
  ##
  ## Reference: bitcoin-core/src/rpc/blockchain.cpp::scanblocks (lines
  ##   2531-2716).
  ##
  ## Supported actions:
  ##   "start"  — run the scan (only this does real work; scanobjects required)
  ##   "status" — no persistent scan state here; returns null (no scan running)
  ##   "abort"  — no scan to abort here; returns false
  ##
  ## Returns (action=="start"):
  ## {
  ##   "from_height":     start_height (int),
  ##   "to_height":       stop_height (int),
  ##   "relevant_blocks": [ <blockhash display-hex>, ... ],
  ##   "completed":       true  (rustoshi/nimrod scan synchronously, so the
  ##                            scan is never aborted partway)
  ## }
  ##
  ## CAVEAT: block filters have FALSE POSITIVES, so relevant_blocks is a
  ## SUPERSET of the truly-matching blocks.  The contract is membership: a
  ## block that genuinely contains a matched script MUST appear.
  ##
  ## Error parity (Core):
  ##   unknown action      -> Core RPC_INVALID_PARAMETER (-8); here we throw
  ##                          RpcInvalidParams to mirror handleScanTxOutSet
  ##                          (the harness gates the action case on "is an
  ##                          error", not the exact code).
  ##   unknown filtertype  -> RPC_INVALID_ADDRESS_OR_KEY (-5) "Unknown filtertype"
  ##   index not enabled   -> RPC_MISC_ERROR (-1) "Index is not enabled for
  ##                          filtertype <name>"
  ##   bad start/stop hght -> RPC_MISC_ERROR (-1) "Invalid start_height" /
  ##                          "Invalid stop_height"
  if params.len < 1 or params[0].kind != JString:
    raise newRpcError(RpcInvalidParams, "action argument is required")

  let action = params[0].getStr()

  # (1) Action dispatch (Core 2578-2596).  nimrod scans synchronously, so there
  # is never an in-progress scan: "status" -> null, "abort" -> false.
  if action == "status":
    return newJNull()
  elif action == "abort":
    return %false
  elif action != "start":
    raise newRpcError(RpcInvalidParams, "Invalid action '" & action & "'")

  # action == "start"

  # Core signature: scanblocks "action" ( [scanobjects] start_height
  #   stop_height "filtertype" options ).  So the positional indices are:
  #     0 = action, 1 = scanobjects, 2 = start_height, 3 = stop_height,
  #     4 = filtertype, 5 = options.

  # (2) filtertype validation (Core 2603-2606).  Default "basic"; only "basic"
  # is a known type.  Unknown -> -5 "Unknown filtertype".  filtertype is
  # positional arg index 4.
  let filterTypeName =
    if params.len >= 5 and params[4].kind == JString and params[4].getStr().len > 0:
      params[4].getStr()
    else:
      "basic"
  if filterTypeName != "basic":
    raise newRpcError(RpcInvalidAddressOrKey, "Unknown filtertype")

  # (3) options.filter_false_positives (Core 2608-2609).  Default false; reading
  # it must never error when absent / null / non-object.  options is arg index 5.
  let filterFalsePositives =
    if params.len >= 6 and params[5].kind == JObject and
       params[5].hasKey("filter_false_positives") and
       params[5]["filter_false_positives"].kind == JBool:
      params[5]["filter_false_positives"].getBool()
    else:
      false

  # (4) scanobjects required for "start" (Core get_array on params[1]).
  if params.len < 2 or params[1].kind != JArray:
    raise newRpcError(RpcMiscError,
                      "scanobjects argument is required for the start action")

  # Build the needle set: the scriptPubKeys to look for in each block filter.
  # Reuse the same descriptor helper scantxoutset uses (addr()/raw()).  Use a
  # seq (not a HashSet) so the order is deterministic for matchAny.
  var needleSet = initHashSet[seq[byte]]()
  for scanobject in params[1]:
    needleSet.incl(rpc.parseScanObject(scanobject))
  var needles: seq[seq[byte]] = @[]
  for n in needleSet:
    needles.add(n)

  # (5) Index-enabled gate (Core 2611-2614: GetBlockFilterIndex==null ->
  # RPC_MISC_ERROR "Index is not enabled for filtertype <name>").
  if rpc.filterIndex == nil or not rpc.filterIndex.enabled:
    raise newRpcError(RpcMiscError,
                      "Index is not enabled for filtertype " & filterTypeName)

  # (6) Height range (Core 2620-2641).  NOTE Core uses RPC_MISC_ERROR (-1) for
  # bad heights here, NOT -8 like scantxoutset.  Default start=genesis(0),
  # default stop=tip.  start_height is positional arg index 2, stop_height is
  # index 3 (filtertype index 4, options index 5).
  let tip = int(rpc.chainState.bestHeight)
  let startHeight =
    if params.len >= 3 and params[2].kind == JInt:
      int(params[2].getBiggestInt())
    else:
      0
  if startHeight < 0 or startHeight > tip:
    raise newRpcError(RpcMiscError, "Invalid start_height")
  let stopHeight =
    if params.len >= 4 and params[3].kind == JInt:
      int(params[3].getBiggestInt())
    else:
      tip
  if stopHeight < startHeight or stopHeight > tip:
    raise newRpcError(RpcMiscError, "Invalid stop_height")

  # (7) Scan loop (Core 2664-2706).  For each height in [start, stop], read the
  # block's basic filter from the index and test it against the needle set.  A
  # height with no filter row means the index is lagging the chain — Core
  # silently skips, but (like getblockfilter) we surface a clear error so a
  # partial/lagging index never returns a misleadingly incomplete list.
  let relevant = newJArray()
  if needles.len > 0:
    for h in startHeight .. stopHeight:
      let blockHashOpt = rpc.chainState.getBlockHashByHeight(int32(h))
      if blockHashOpt.isNone:
        raise newRpcError(RpcMiscError,
          "Filter not found. Block filters are still in the process of being indexed.")
      let blockHash = blockHashOpt.get()

      let filterOpt = rpc.filterIndex.getFilter(int32(h), blockHash)
      if filterOpt.isNone:
        raise newRpcError(RpcMiscError,
          "Filter not found. Block filters are still in the process of being indexed.")
      let bf = filterOpt.get()

      if not gcsMod.matchAny(bf.filter, needles):
        continue

      # (Core 2681-2688 CheckBlockFilterMatches.)  Optional re-scan to drop GCS
      # false positives: re-extract the block's real filter element set and
      # require a byte-exact needle match.  This is a strict subset — it can
      # only REMOVE false positives, never a genuine match — so the funded-block
      # contract holds with or without it.
      if filterFalsePositives:
        let blkOpt = rpc.chainState.db.getBlock(blockHash)
        if blkOpt.isNone:
          continue
        let blk = blkOpt.get()
        var spentOutputs: seq[gcsMod.SpentOutput] = @[]
        let bidxOpt = rpc.chainState.db.getBlockIndex(blockHash)
        if bidxOpt.isSome:
          let undoOpt = rpc.chainState.getBlockUndoFromFile(
            bidxOpt.get(), blk.header.prevBlock)
          if undoOpt.isSome:
            for txUndo in undoOpt.get().txUndo:
              for spent in txUndo.prevOutputs:
                spentOutputs.add(gcsMod.SpentOutput(
                  output: spent.output,
                  height: spent.height,
                  isCoinbase: spent.isCoinbase))
        let elements = gcsMod.extractBasicFilterElements(blk, spentOutputs)
        var elemSet = initHashSet[seq[byte]]()
        for e in elements:
          elemSet.incl(e)
        var realMatch = false
        for n in needles:
          if n in elemSet:
            realMatch = true
            break
        if not realMatch:
          continue

      # Display-order block hash, matching Core's GetHex() (reversed/big-endian).
      relevant.add(%reverseHex(toHex(array[32, byte](blockHash))))

  # (8) Return (Core 2708-2711).  The synchronous scan is never aborted, so
  # `completed` is always true.
  result = newJObject()
  result["from_height"] = %startHeight
  result["to_height"] = %stopHeight
  result["relevant_blocks"] = relevant
  result["completed"] = %true

proc handleScrubUnspendable*(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Operator-invoked one-shot scrub: walk the chainstate UTXO column
  ## family and delete every entry whose scriptPubKey is provably
  ## unspendable per `CScript::IsUnspendable()` (OP_RETURN-prefixed OR
  ## > MAX_SCRIPT_SIZE).
  ##
  ## Closes the legacy datadir gap left by the byte-identity write-time
  ## filter (chainstate commit 94b7755): existing chainstates created
  ## BEFORE that fix still carry orphan OP_RETURN coins from segwit
  ## coinbase witness commitments; `gettxoutsetinfo` reads ~2x the correct
  ## count on those datadirs. The scrub removes them in place.
  ##
  ## Idempotent — running twice removes 0 the second time.
  ## Does NOT run automatically on startup; operator-invoked only.
  ##
  ## Arguments: (none — params ignored)
  ##
  ## Returns:
  ##   { "removed": <uint>, "bytes_freed": <uint> }
  discard params  # no parameters
  let res = scrubUnspendable(rpc.chainState)
  result = %*{
    "removed": res.removed,
    "bytes_freed": res.bytesFreed
  }

# ============================================================================
# Wallet RPCs
# ============================================================================

proc getTargetWallet(rpc: RpcServer): Wallet {.gcsafe.} =
  ## Get the wallet targeted by the current request
  ## Uses currentWalletName set by processClient based on URL
  ## Falls back to default wallet if only one loaded

  # If wallet manager is configured, use it
  if rpc.walletManager != nil:
    if rpc.currentWalletName != "":
      let lwOpt = rpc.walletManager.getWallet(rpc.currentWalletName)
      if lwOpt.isNone:
        raise newRpcError(RpcMiscError, "Requested wallet does not exist or is not loaded")
      return lwOpt.get().wallet
    else:
      # No specific wallet requested, check for default
      let count = rpc.walletManager.getWalletCount()
      if count == 0:
        raise newRpcError(RpcMiscError, "No wallet is loaded. Load a wallet first using loadwallet or create one with createwallet.")
      elif count == 1:
        # Return the single loaded wallet
        let lwOpt = rpc.walletManager.getDefaultWallet()
        if lwOpt.isSome:
          return lwOpt.get().wallet
        raise newRpcError(RpcMiscError, "No wallet is loaded")
      else:
        raise newRpcError(RpcMiscError, "Wallet file not specified. Use /wallet/<walletname> or specify wallet_name with -rpcwallet option.")

  # Fall back to legacy single wallet mode
  if rpc.wallet == nil:
    raise newRpcError(RpcMiscError, "wallet not loaded")
  return rpc.wallet

proc getTargetLoadedWallet(rpc: RpcServer): LoadedWallet {.gcsafe.} =
  ## LoadedWallet (wallet + sqlite handle) counterpart of getTargetWallet,
  ## for handlers that must persist rows (importdescriptors). Returns nil in
  ## legacy single-wallet mode / when no manager wallet matches; callers must
  ## treat nil as "no sqlite persistence available" (in-memory import only).
  if rpc.walletManager == nil:
    return nil
  if rpc.currentWalletName != "":
    let lwOpt = rpc.walletManager.getWallet(rpc.currentWalletName)
    if lwOpt.isSome:
      return lwOpt.get()
    return nil
  let lwOpt = rpc.walletManager.getDefaultWallet()
  if lwOpt.isSome:
    return lwOpt.get()
  nil

# ============================================================================
# Wallet Management RPCs
# ============================================================================

proc handleCreateWallet(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Create a new wallet
  ## Reference: Bitcoin Core wallet/rpc/wallet.cpp createwallet
  ##
  ## Arguments:
  ## 1. wallet_name (string, required) - Name of wallet to create
  ## 2. disable_private_keys (bool, optional, default=false) - Create watch-only
  ## 3. blank (bool, optional, default=false) - Create blank wallet without keys
  ## 4. passphrase (string, optional) - Encrypt wallet with passphrase
  ## 5. avoid_reuse (bool, optional, default=false) - Track address reuse
  ## 6. descriptors (bool, optional, default=true) - Create descriptor wallet
  ## 7. load_on_startup (bool, optional) - Add to auto-load list
  ##
  ## Returns: { "name": wallet_name, "warning": "" }

  if rpc.walletManager == nil:
    raise newRpcError(RpcMiscError, "wallet functionality not enabled")

  if params.len < 1 or params[0].kind != JString:
    raise newRpcError(RpcInvalidParams, "wallet_name required")

  let walletName = params[0].getStr()

  var options = WalletCreateOptions()

  if params.len >= 2 and params[1].kind == JBool:
    options.disablePrivateKeys = params[1].getBool()

  if params.len >= 3 and params[2].kind == JBool:
    options.blank = params[2].getBool()

  if params.len >= 4 and params[3].kind == JString:
    options.passphrase = params[3].getStr()

  if params.len >= 5 and params[4].kind == JBool:
    options.avoidReuse = params[4].getBool()

  if params.len >= 6 and params[5].kind == JBool:
    options.descriptors = params[5].getBool()
    # Core: legacy (non-descriptor) wallets can no longer be created at all.
    # Reference: bitcoin-core/src/wallet/rpc/wallet.cpp:402-405 (-4).
    if not options.descriptors:
      raise newRpcError(RpcWalletError,
        "descriptors argument must be set to \"true\"; it is no longer " &
        "possible to create a legacy wallet.")

  if params.len >= 7 and params[6].kind == JBool:
    options.loadOnStartup = params[6].getBool()

  # Core: a passphrase only encrypts private keys, so it cannot be combined
  # with disable_private_keys. Reference: bitcoin-core/src/wallet/wallet.cpp
  # CreateWallet:408-412 (FAILED_CREATE -> RPC_WALLET_ERROR -4).
  if options.disablePrivateKeys and options.passphrase.len > 0:
    raise newRpcError(RpcWalletError,
      "Passphrase provided but private keys are disabled. A passphrase is " &
      "only used to encrypt private keys, so cannot be used for wallets " &
      "with private keys disabled.")

  try:
    let (lw, warnings) = rpc.walletManager.createWallet(walletName, options)
    var resp = %*{
      "name": lw.name,
      "warning": if warnings.len > 0: warnings.join("; ") else: ""
    }
    # Core shape: optional "warnings" string array (wallet.cpp:425-427).
    # The joined "warning" string above is kept for backward compatibility.
    if warnings.len > 0:
      var warr = newJArray()
      for wmsg in warnings:
        warr.add(%wmsg)
      resp["warnings"] = warr
    resp
  except WalletManagerError as e:
    raise newRpcError(RpcWalletError, e.msg)
  except CatchableError as e:
    raise newRpcError(RpcWalletError, "Failed to create wallet: " & e.msg)

proc handleLoadWallet(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Load a wallet from disk
  ## Reference: Bitcoin Core wallet/rpc/wallet.cpp loadwallet
  ##
  ## Arguments:
  ## 1. filename (string, required) - Wallet name or path
  ## 2. load_on_startup (bool, optional) - Add to auto-load list
  ##
  ## Returns: { "name": wallet_name, "warning": "" }

  if rpc.walletManager == nil:
    raise newRpcError(RpcMiscError, "wallet functionality not enabled")

  if params.len < 1 or params[0].kind != JString:
    raise newRpcError(RpcInvalidParams, "filename required")

  let filename = params[0].getStr()
  var loadOnStartup = none(bool)

  if params.len >= 2 and params[1].kind == JBool:
    loadOnStartup = some(params[1].getBool())

  try:
    let (lw, warnings) = rpc.walletManager.loadWallet(filename, loadOnStartup)
    var result = %*{
      "name": lw.name,
      "warning": if warnings.len > 0: warnings.join("; ") else: ""
    }
    result
  except WalletManagerError as e:
    raise newRpcError(RpcMiscError, e.msg)
  except CatchableError as e:
    raise newRpcError(RpcMiscError, "Failed to load wallet: " & e.msg)

proc handleUnloadWallet(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Unload a wallet from memory
  ## Reference: Bitcoin Core wallet/rpc/wallet.cpp unloadwallet
  ##
  ## Arguments:
  ## 1. wallet_name (string, optional) - Wallet name (defaults to current wallet)
  ## 2. load_on_startup (bool, optional) - Update auto-load setting
  ##
  ## Returns: { "warning": "" }

  if rpc.walletManager == nil:
    raise newRpcError(RpcMiscError, "wallet functionality not enabled")

  var walletName = rpc.currentWalletName
  var loadOnStartup = none(bool)

  if params.len >= 1 and params[0].kind == JString:
    walletName = params[0].getStr()

  if params.len >= 2 and params[1].kind == JBool:
    loadOnStartup = some(params[1].getBool())

  # If no wallet specified, use current target
  if walletName == "":
    let count = rpc.walletManager.getWalletCount()
    if count == 0:
      raise newRpcError(RpcMiscError, "No wallet is loaded")
    elif count == 1:
      let lwOpt = rpc.walletManager.getDefaultWallet()
      if lwOpt.isSome:
        walletName = lwOpt.get().name
    else:
      raise newRpcError(RpcMiscError, "wallet_name required when multiple wallets are loaded")

  try:
    let warnings = rpc.walletManager.unloadWallet(walletName, loadOnStartup)
    %*{
      "warning": if warnings.len > 0: warnings.join("; ") else: ""
    }
  except WalletManagerError as e:
    raise newRpcError(RpcMiscError, e.msg)
  except CatchableError as e:
    raise newRpcError(RpcMiscError, "Failed to unload wallet: " & e.msg)

proc handleListWallets(rpc: RpcServer, params: JsonNode): JsonNode =
  ## List currently loaded wallets
  ## Reference: Bitcoin Core wallet/rpc/wallet.cpp listwallets
  ##
  ## Returns: Array of wallet names

  if rpc.walletManager == nil:
    # Fall back to legacy mode
    if rpc.wallet != nil:
      return %*["default"]
    return %*[]

  let wallets = rpc.walletManager.listLoadedWallets()
  var result = newJArray()
  for name in wallets:
    result.add(%name)
  result

proc handleListWalletDir(rpc: RpcServer, params: JsonNode): JsonNode =
  ## List wallets in the wallet directory
  ## Reference: Bitcoin Core wallet/rpc/wallet.cpp listwalletdir
  ##
  ## Returns: { "wallets": [{"name": "wallet1"}, ...] }

  if rpc.walletManager == nil:
    raise newRpcError(RpcMiscError, "wallet functionality not enabled")

  let wallets = rpc.walletManager.listWalletDir()
  var walletsArray = newJArray()
  for (name, _) in wallets:
    walletsArray.add(%*{"name": name})

  %*{"wallets": walletsArray}

proc handleGetNewAddress(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Generate a new address for receiving payments
  ## Reference: Bitcoin Core wallet/rpc/addresses.cpp getnewaddress
  ##
  ## Arguments:
  ## 1. label (string, optional) - Account label (ignored for now)
  ## 2. address_type (string, optional) - Address type: "legacy", "p2sh-segwit", "bech32", "bech32m"
  ##
  ## Returns: New address string
  ##
  ## Note: Requires wallet to be loaded

  var w = rpc.getTargetWallet()

  # Watch-only (disable_private_keys) wallets have no keypool to draw from.
  # Core: RPC_WALLET_ERROR "Error: This wallet has no available keys"
  # (wallet/rpc/addresses.cpp getnewaddress -> CanGetAddresses).
  if w.privateKeysDisabled:
    raise newRpcError(RpcWalletError, "Error: This wallet has no available keys")

  # Parse address type (default to bech32/P2WPKH)
  var addressType = "bech32"
  if params.len >= 2 and params[1].kind == JString:
    addressType = params[1].getStr()

  try:
    let addrStr = w.getNewAddressByTypeName(addressType)
    # Persist the keypool advance immediately so a crash can't reissue this
    # address (gap-limit safety). DATA-LOSS FIX wa0fq5wtk.
    rpc.persistTargetWallet()
    %addrStr
  except WalletError as e:
    raise newRpcError(RpcMiscError, e.msg)

proc handleSetHdSeed(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Set / restore the wallet's HD master seed from a known value, making
  ## key derivation deterministic so a wallet can be recovered from a
  ## seed (or BIP-39 mnemonic) alone.
  ##
  ## Reference: Bitcoin Core wallet/rpc/backup.cpp sethdseed
  ## (CWallet::SetHDSeed + keypool flush). nimrod has no on-disk WIF seed
  ## blob to import, so this accepts the raw seed (or mnemonic) directly and
  ## re-derives the master key via BIP-32 HMAC-SHA512(key="Bitcoin seed").
  ##
  ## Arguments (positional, Core-compatible ordering with an extension):
  ##   1. newkeypool (bool, optional, default=true) — flush+regenerate keys.
  ##      Always effectively true here (we re-derive every account).
  ##   2. seed (string, optional) — the seed material. Accepted forms:
  ##        - hex string, 16..64 bytes  (raw BIP-32 seed; mirrors ouroboros)
  ##        - a BIP-39 mnemonic phrase (space-separated words)
  ##      If omitted, a fresh random 32-byte seed is generated.
  ##
  ## Returns: { "seed_hex", "xprv", "xpub" } (xprv null when no privkeys).
  var w = rpc.getTargetWallet()

  # Core: sethdseed is a key-bearing operation, refused on watch-only wallets.
  # Reference: wallet/rpc/backup.cpp sethdseed -> RPC_WALLET_ERROR (-4)
  # "Cannot set a HD seed to a wallet with private keys disabled".
  if w.privateKeysDisabled:
    raise newRpcError(RpcWalletError,
      "Cannot set a HD seed to a wallet with private keys disabled")

  if w.isEncrypted and w.isLocked:
    raise newRpcError(RpcWalletError,
      "Error: Please enter the wallet passphrase with walletpassphrase first.")

  # Parse the seed argument. Core puts newkeypool first, seed second; we
  # accept the seed at index 0 too when it's clearly a string (lenient).
  var seedArg = ""
  if params.len >= 2 and params[1].kind == JString:
    seedArg = params[1].getStr()
  elif params.len >= 1 and params[0].kind == JString:
    seedArg = params[0].getStr()

  var seed: seq[byte]
  if seedArg.len == 0:
    # Generate a fresh random 32-byte seed.
    seed = newSeq[byte](32)
    var arr: array[32, byte]
    if not urandom(arr):
      raise newRpcError(RpcMiscError, "failed to generate random seed")
    for i in 0 ..< 32: seed[i] = arr[i]
  elif " " in seedArg.strip():
    # Looks like a BIP-39 mnemonic phrase.
    if not validateMnemonic(seedArg.strip()):
      raise newRpcError(RpcInvalidParams, "invalid BIP-39 mnemonic")
    let s = mnemonicToSeed(seedArg.strip())
    seed = newSeq[byte](64)
    for i in 0 ..< 64: seed[i] = s[i]
  else:
    # Raw hex seed.
    let h = seedArg.strip()
    if h.len mod 2 != 0:
      raise newRpcError(RpcInvalidParams, "seed hex must have even length")
    for c in h:
      if c notin {'0'..'9', 'a'..'f', 'A'..'F'}:
        raise newRpcError(RpcInvalidParams, "seed must be valid hex or a mnemonic")
    seed = hexToBytes(h)
    if seed.len < 16 or seed.len > 64:
      raise newRpcError(RpcInvalidParams, "seed must be 16-64 bytes")

  try:
    w.setHdSeed(seed)
  except WalletError as e:
    raise newRpcError(RpcInvalidParams, e.msg)

  let mainnet = w.mainnet
  var seedHex = ""
  for b in seed: seedHex.add(b.toHex(2).toLowerAscii())

  var xprv = newJNull()
  if w.masterKey.isPrivate:
    xprv = %serializeExtendedKey(w.masterKey, mainnet)
  let xpub = %serializeExtendedKey(neuter(w.masterKey), mainnet)

  %*{
    "seed_hex": seedHex,
    "xprv": xprv,
    "xpub": xpub
  }

proc rescanWalletRange(rpc: RpcServer, w: Wallet,
                       startHeight, stopHeight: int32) {.gcsafe.} =
  ## Walk the active chain from startHeight..stopHeight (inclusive) and scan
  ## each block into the given wallet's ledger via scanBlockForWallet — the
  ## backward counterpart of the block-connect scan. This rediscovers every
  ## wallet-owned output funded in the range (crediting the UTXO set + history)
  ## and debits inputs that spent wallet coins. Mirrors Bitcoin Core's
  ## CWallet::ScanForWalletTransactions, which replays the block range through
  ## the same transaction-recognition path used at block-connect.
  ##
  ## scanBlockForWallet is idempotent ({txid,vout} set inserts; spends re-delete
  ## already-absent entries), so re-scanning an already-scanned block is a no-op.
  if w == nil:
    return
  # Wallet is a ref object; a local var binding mutates the same instance.
  var wv = w
  var h = startHeight
  while h <= stopHeight:
    let hashOpt = rpc.chainState.db.getBlockHashByHeight(h)
    if hashOpt.isSome:
      let blkOpt = rpc.chainState.db.getBlock(hashOpt.get())
      if blkOpt.isSome:
        try:
          wv.scanBlockForWallet(blkOpt.get(), h)
        except CatchableError:
          discard  # never let a single bad block abort the whole rescan
    inc h

proc handleRescanBlockchain(rpc: RpcServer, params: JsonNode): JsonNode =
  ## rescanblockchain ( start_height stop_height )
  ##
  ## Rescan the local blockchain for transactions affecting the wallet, over an
  ## optional [start_height, stop_height] range. This is the REAL wallet rescan
  ## (distinct from scantxoutset, which scans the chainstate UTXO set without
  ## touching any wallet): it credits the wallet UTXO ledger + transaction
  ## history for every wallet-owned output found in the range, so a wallet
  ## restored from seed (which derives keys but does NOT scan the chain) can
  ## rediscover its on-chain funds.
  ##
  ## Reference: bitcoin-core/src/wallet/rpc/transactions.cpp rescanblockchain ->
  ## CWallet::ScanForWalletTransactions.
  ##
  ## Arguments:
  ##   1. start_height (numeric, optional, default=0)
  ##   2. stop_height  (numeric, optional, default=tip)
  ##
  ## Returns: { "start_height": <int>, "stop_height": <int> }
  let w = rpc.getTargetWallet()

  if rpc.chainState == nil:
    raise newRpcError(RpcMiscError, "no chain state")
  let tipHeight = rpc.chainState.bestHeight

  var startHeight = 0'i32
  if params.len >= 1 and params[0].kind != JNull:
    let sh = params[0].getInt()
    if sh < 0 or int32(sh) > tipHeight:
      raise newRpcError(RpcInvalidParams, "Invalid start_height")
    startHeight = int32(sh)

  var stopHeight = tipHeight
  if params.len >= 2 and params[1].kind != JNull:
    let st = params[1].getInt()
    if st < 0 or int32(st) > tipHeight:
      raise newRpcError(RpcInvalidParams, "Invalid stop_height")
    elif int32(st) < startHeight:
      raise newRpcError(RpcInvalidParams, "stop_height must be greater than start_height")
    stopHeight = int32(st)

  rpc.rescanWalletRange(w, startHeight, stopHeight)

  %*{
    "start_height": startHeight,
    "stop_height": stopHeight
  }

proc handleImportPrivKey(rpc: RpcServer, params: JsonNode): JsonNode =
  ## importprivkey "privkey" ( "label" rescan )
  ##
  ## Add a private key (as returned by dumpprivkey / a WIF string) to the
  ## wallet. The key's standard address(es) are registered in the keystore so
  ## the wallet recognises and can spend coins paying them. If rescan is true
  ## (the default), the existing chain is rescanned so the key's already-on-chain
  ## funds are credited immediately.
  ##
  ## Reference: bitcoin-core/src/wallet/rpc/backup.cpp importprivkey ->
  ## CWallet::ImportPrivKeys + (optionally) ScanForWalletTransactions.
  ##
  ## Arguments:
  ##   1. privkey (string, required) — the WIF-encoded private key
  ##   2. label   (string, optional, default="") — label for the address(es)
  ##   3. rescan  (bool, optional, default=true) — rescan the chain afterwards
  ##
  ## Returns: null on success (Core shape).
  var w = rpc.getTargetWallet()

  # Core: private keys can never enter a disable_private_keys wallet.
  # Reference: wallet/rpc/backup.cpp:224-226 equivalent (-4).
  if w.privateKeysDisabled:
    raise newRpcError(RpcWalletError,
      "Cannot import private keys to a wallet with private keys disabled")

  if w.isEncrypted and w.isLocked:
    raise newRpcError(RpcWalletError,
      "Error: Please enter the wallet passphrase with walletpassphrase first.")

  if params.len < 1 or params[0].kind != JString:
    raise newRpcError(RpcInvalidParams, "privkey (WIF string) is required")
  let wif = params[0].getStr()

  let label = if params.len >= 2 and params[1].kind == JString: params[1].getStr() else: ""
  let doRescan = if params.len >= 3 and params[2].kind == JBool: params[2].getBool() else: true

  var privKey: PrivateKey
  var compressed = true
  try:
    let (k, c, _) = decodeWIF(wif)
    privKey = k
    compressed = c
  except CatchableError:
    raise newRpcError(RpcInvalidAddressOrKey, "Invalid private key encoding")

  var addrs: seq[string]
  try:
    addrs = w.importPrivateKey(privKey, compressed)
  except CatchableError as e:
    raise newRpcError(RpcWalletError, "Error adding key to wallet: " & e.msg)

  # Apply the label (if any) to the imported address(es).
  if label.len > 0:
    for a in addrs:
      w.labels[a] = label

  # Rescan the existing chain so funds already paid to the imported key are
  # credited now (Core importprivkey rescan=true default).
  if doRescan and rpc.chainState != nil:
    rpc.rescanWalletRange(w, 0'i32, rpc.chainState.bestHeight)

  newJNull()

proc handleDumpPrivKey(rpc: RpcServer, params: JsonNode): JsonNode =
  ## dumpprivkey "address"
  ##
  ## Reveal the WIF-encoded private key for an address the wallet owns. The
  ## companion to importprivkey: dump a key from one wallet, import it into
  ## another. Reference: bitcoin-core/src/wallet/rpc/backup.cpp dumpprivkey.
  ##
  ## Arguments:
  ##   1. address (string, required) — a wallet address
  ##
  ## Returns: the private key as a WIF string.
  let w = rpc.getTargetWallet()

  if w.isEncrypted and w.isLocked:
    raise newRpcError(RpcWalletError,
      "Error: Please enter the wallet passphrase with walletpassphrase first.")

  if params.len < 1 or params[0].kind != JString:
    raise newRpcError(RpcInvalidParams, "address is required")
  let address = params[0].getStr()

  let wifOpt = w.dumpPrivKey(address)
  if wifOpt.isNone:
    raise newRpcError(RpcWalletError,
      "Private key for address " & address & " is not known")
  %wifOpt.get()

proc handleGetRawChangeAddress(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Generate a new change address
  ## Reference: Bitcoin Core wallet/rpc/addresses.cpp getrawchangeaddress
  ##
  ## Arguments:
  ## 1. address_type (string, optional) - Address type: "legacy", "p2sh-segwit", "bech32", "bech32m"
  ##
  ## Returns: New change address string

  var w = rpc.getTargetWallet()

  # Watch-only wallets cannot derive change addresses (no keys). Core: -4.
  if w.privateKeysDisabled:
    raise newRpcError(RpcWalletError, "Error: This wallet has no available keys")

  var addressType = "bech32"
  if params.len >= 1 and params[0].kind == JString:
    addressType = params[0].getStr()

  try:
    # Use the internal chain for change addresses
    let addrType = case addressType.toLowerAscii()
      of "legacy": P2PKH
      of "p2sh-segwit": P2SH
      of "bech32": P2WPKH
      of "bech32m": P2TR
      else:
        raise newException(WalletError, "unknown address type: " & addressType)

    let addrStr = w.getNewAddressStr(addrType, -1, true)
    # Persist the internal keypool advance (gap-limit safety). DATA-LOSS FIX.
    rpc.persistTargetWallet()
    %addrStr
  except WalletError as e:
    raise newRpcError(RpcMiscError, e.msg)

proc handleGetBalance(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Get wallet balance
  ## Reference: Bitcoin Core wallet/rpc/coins.cpp getbalance

  let w = rpc.getTargetWallet()
  # Core's getbalance reports only spendable coins: confirmed, and for coinbase
  # past the 100-confirmation maturity window. Sum the maturity-filtered set at
  # the current chain tip (getSpendableBalance), mirroring the
  # premature_spend_of_coinbase rule that validation/mempool enforce on spend.
  # Falls back to the raw total only when no chain tip is known.
  let currentHeight = if rpc.chainState != nil: rpc.chainState.bestHeight else: 0'i32
  let balance = if currentHeight > 0:
    w.getSpendableBalance(currentHeight)
  else:
    w.getBalance()
  %*(float64(int64(balance)) / 100_000_000.0)

proc handleListUnspent(rpc: RpcServer, params: JsonNode): JsonNode =
  ## List unspent transaction outputs
  ## Reference: Bitcoin Core wallet/rpc/coins.cpp listunspent
  ##
  ## Arguments:
  ## 1. minconf (numeric, optional, default=1) - Minimum confirmations
  ## 2. maxconf (numeric, optional, default=9999999) - Maximum confirmations
  ##
  ## Returns: Array of UTXOs

  let w = rpc.getTargetWallet()

  let minconf = if params.len >= 1: params[0].getInt() else: 1
  let maxconf = if params.len >= 2: params[1].getInt() else: 9999999

  let currentHeight = if rpc.chainState != nil: rpc.chainState.bestHeight else: 0'i32
  let mainnet = rpc.params.network == Mainnet

  var utxoArray = newJArray()
  for _, utxo in w.utxos:
    let confs = if utxo.height > 0: currentHeight - utxo.height + 1 else: 0
    if confs >= minconf and confs <= maxconf:
      let addrOpt = extractAddressFromScript(utxo.output.scriptPubKey, mainnet)
      # Immature coinbase coins are listed but flagged non-spendable/unsafe,
      # matching Core's AvailableCoins semantics (a coinbase at height H is
      # spendable once currentHeight - H >= COINBASE_MATURITY, i.e. it has
      # COINBASE_MATURITY+1 confirmations). isMatureCoinbase returns true for
      # all non-coinbase coins.
      let spendable = utxo.isMatureCoinbase(currentHeight)
      var entry = %*{
        "txid": reverseHex(toHex(array[32, byte](utxo.outpoint.txid))),
        "vout": utxo.outpoint.vout,
        "amount": float64(int64(utxo.output.value)) / 100_000_000.0,
        "confirmations": confs,
        "scriptPubKey": toHex(utxo.output.scriptPubKey),
        "spendable": spendable,
        "solvable": true,
        "safe": spendable
      }
      if addrOpt.isSome:
        entry["address"] = %addrOpt.get()
      utxoArray.add(entry)

  utxoArray

proc handleGetWalletInfo(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Get wallet information
  ## Reference: Bitcoin Core wallet/rpc/wallet.cpp getwalletinfo

  let w = rpc.getTargetWallet()

  # Get wallet name from wallet manager if available
  var walletName = "default"
  if rpc.walletManager != nil and rpc.currentWalletName != "":
    walletName = rpc.currentWalletName
  elif rpc.walletManager != nil:
    let lwOpt = rpc.walletManager.getDefaultWallet()
    if lwOpt.isSome:
      walletName = lwOpt.get().name

  let balance = w.getBalance()
  let txCount = w.utxos.len  # Simplified: count UTXOs as proxy for tx count
  let currentHeight = if rpc.chainState != nil: rpc.chainState.bestHeight else: 0'i32
  let immatureBalance = w.getImmatureBalance(currentHeight)

  # private_keys_enabled = !WALLET_FLAG_DISABLE_PRIVATE_KEYS — derived from
  # the persisted flag, no longer hardcoded true. A disable_private_keys
  # wallet has no keypool. Reference: bitcoin-core/src/wallet/rpc/wallet.cpp
  # getwalletinfo (private_keys_enabled at :98, flags array at :116-128).
  let keypool = if w.privateKeysDisabled: 0 else: 20
  var info = %*{
    "walletname": walletName,
    "walletversion": 1,
    "format": "nimrod",
    "balance": float64(int64(balance)) / 100_000_000.0,
    "unconfirmed_balance": 0.0,
    "immature_balance": float64(int64(immatureBalance)) / 100_000_000.0,
    "txcount": txCount,
    "keypoolsize": keypool,
    "keypoolsize_hd_internal": keypool,
    "paytxfee": 0.0,
    "private_keys_enabled": not w.privateKeysDisabled,
    "avoid_reuse": false,
    "scanning": false,
    "descriptors": false,
    "external_signer": false,
    "blank": (w.accounts.len == 0 and not w.privateKeysDisabled),
    "unlocked_until": (if w.isEncrypted and not w.isLocked: w.unlockExpiry else: 0)
  }
  # Core's flags string array (only the flags nimrod models are emitted).
  var flags = newJArray()
  if w.privateKeysDisabled:
    flags.add(%"disable_private_keys")
  info["flags"] = flags
  info

# ============================================================================
# Wallet Send/Receive RPCs
# ============================================================================

proc handleSendToAddress(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Send an amount to a given address
  ## Reference: Bitcoin Core wallet/rpc/spend.cpp sendtoaddress
  ##
  ## Arguments:
  ## 1. address (string, required) - The bitcoin address to send to
  ## 2. amount (numeric, required) - The amount in BTC to send
  ## 3. comment (string, optional) - A comment used to store the transaction
  ## 4. comment_to (string, optional) - A comment to store the recipient name
  ## 5. subtractfeefromamount (bool, optional, default=false) - Deduct fee from amount
  ## 6. replaceable (bool, optional, default=true) - Allow RBF
  ## 7. conf_target (numeric, optional, default=6) - Confirmation target in blocks
  ## 8. estimate_mode (string, optional, default="economical") - Fee estimation mode
  ##
  ## Returns: txid (string) - The transaction ID

  var w = rpc.getTargetWallet()

  # The defining watch-only property: watched funds are observable, never
  # spendable. Core: RPC_WALLET_ERROR (-4) "Error: Private keys are disabled
  # for this wallet" (wallet/rpc/spend.cpp send-family guard).
  if w.privateKeysDisabled:
    raise newRpcError(RpcWalletError,
      "Error: Private keys are disabled for this wallet")

  if params.len < 2:
    raise newRpcError(RpcInvalidParams, "missing address and/or amount parameter")

  let addressStr = params[0].getStr()
  var amount: float64

  if params[1].kind == JFloat:
    amount = params[1].getFloat()
  elif params[1].kind == JInt:
    amount = float64(params[1].getInt())
  else:
    raise newRpcError(RpcInvalidParams, "amount must be a number")

  # Validate amount
  if amount <= 0:
    raise newRpcError(RpcInvalidParams, "amount must be positive")
  if amount > 21000000.0:
    raise newRpcError(RpcInvalidParams, "amount exceeds max supply")

  # Convert BTC to satoshis
  let satoshis = Satoshi(int64(amount * 100_000_000.0))

  # Parse optional parameters
  let subtractFee = if params.len >= 5 and params[4].kind == JBool: params[4].getBool() else: false
  let replaceable = if params.len >= 6 and params[5].kind == JBool: params[5].getBool() else: true
  let confTarget = if params.len >= 7: params[6].getInt() else: 6

  # Validate and decode address
  var destAddr: Address
  try:
    destAddr = decodeAddress(addressStr)
  except AddressError as e:
    raise newRpcError(RpcInvalidAddressOrKey, "invalid address: " & e.msg)

  # Check if wallet is locked
  if w.isEncrypted and w.isLocked:
    raise newRpcError(RpcMiscError, "wallet is locked; use walletpassphrase to unlock")

  # Get fee rate from fee estimator
  var feeRate: float64
  if rpc.feeEstimator != nil:
    feeRate = rpc.feeEstimator.estimateFee(confTarget)
  else:
    feeRate = FallbackFeeRate

  # Create output
  let scriptPubKey = scriptPubKeyForAddress(destAddr)
  var outputs = @[TxOut(value: satoshis, scriptPubKey: scriptPubKey)]

  # Create transaction
  var tx: Transaction
  try:
    tx = w.createTransaction(outputs, feeRate)
  except WalletError as e:
    raise newRpcError(RpcTransactionError, e.msg)
  except CoinSelectionError as e:
    raise newRpcError(RpcTransactionError, e.msg)

  # If subtractfeefromamount, adjust the output
  if subtractFee:
    # Calculate fee based on transaction size
    let weight = validation.calculateTransactionWeight(tx)
    let estFee = Satoshi(int64(float64(weight) / 4.0 * feeRate))

    if int64(satoshis) <= int64(estFee):
      raise newRpcError(RpcTransactionError, "amount too small to subtract fee")

    # Recreate transaction with adjusted amount
    let adjustedAmount = Satoshi(int64(satoshis) - int64(estFee))
    outputs = @[TxOut(value: adjustedAmount, scriptPubKey: scriptPubKey)]
    try:
      tx = w.createTransaction(outputs, feeRate)
    except WalletError as e:
      raise newRpcError(RpcTransactionError, e.msg)
    except CoinSelectionError as e:
      raise newRpcError(RpcTransactionError, e.msg)

  # Set RBF-enable sequence if replaceable
  if replaceable:
    for i in 0 ..< tx.inputs.len:
      tx.inputs[i].sequence = 0xfffffffd'u32  # RBF signal

  # Get UTXOs for signing
  var utxos: seq[WalletUtxo]
  for input in tx.inputs:
    if input.prevOut in w.utxos:
      utxos.add(w.utxos[input.prevOut])
    else:
      raise newRpcError(RpcTransactionError, "input UTXO not found in wallet")

  # Sign the transaction
  try:
    if not w.signTransaction(tx, utxos):
      raise newRpcError(RpcTransactionError, "failed to sign transaction")
  except WalletError as e:
    raise newRpcError(RpcTransactionError, "signing error: " & e.msg)

  let txid = tx.txid()
  let txidHex = reverseHex(toHex(array[32, byte](txid)))

  # Submit to mempool
  var mp = rpc.mempool
  let acceptResult = mp.acceptTransaction(tx, rpc.crypto)

  if not acceptResult.isOk:
    raise newRpcError(RpcTransactionRejected, "mempool rejected: " & acceptResult.error)

  # Record the wallet transaction-history entry NOW, before the spent UTXOs are
  # removed below — mirrors Bitcoin Core CWallet::CommitTransaction inserting
  # the wtx into mapWallet at commit time. The input values come from the live
  # ledger (the prevouts we are about to spend are still present), so the spend
  # debit / fee are captured correctly even though the block scan that later
  # confirms this tx will no longer see those prevouts in the ledger.
  block recordSend:
    var inputValues: seq[Satoshi]
    for input in tx.inputs:
      if input.prevOut in w.utxos:
        inputValues.add(w.utxos[input.prevOut].output.value)
    w.recordOutgoingTx(tx, inputValues, getTime().toUnix())

  # Remove spent UTXOs from wallet
  for input in tx.inputs:
    w.removeUtxo(input.prevOut)

  # Add change output back to wallet if it's ours
  for voutIdx, output in tx.outputs:
    let keyOpt = w.findKeyForScript(output.scriptPubKey)
    if keyOpt.isSome:
      let key = keyOpt.get()
      let outpoint = OutPoint(txid: txid, vout: uint32(voutIdx))
      let isInternal = key.path.contains("/1/")
      w.addUtxo(outpoint, output, 0, key.path, isInternal, false)

  # Persist the spend: removed prevouts + added change + the outgoing history
  # record must all survive an unclean exit, otherwise a crash here would let
  # coin-selection re-spend the already-broadcast inputs (double-spend attempt)
  # or lose the send from listtransactions. DATA-LOSS FIX wa0fq5wtk.
  rpc.persistTargetWallet()

  # Broadcast to peers
  if rpc.peerManager != nil:
    asyncSpawn rpc.peerManager.broadcastTx(tx)

  %txidHex

# ============================================================================
# Wallet transaction-history helpers (listtransactions / gettransaction)
# ============================================================================
# These read from the wallet's persistent transaction-history ledger
# (Wallet.txHistory / txOrder), populated at block-connect scan time by
# wallet.scanBlockForWallet -> recordWalletTx. The live UTXO set
# (Wallet.utxos) only knows about UNSPENT coins, so it cannot report a spend;
# the history ledger is what makes a "send" entry visible. Field shapes, sign
# conventions and category names mirror Bitcoin Core wallet/rpc/transactions.cpp
# (ListTransactions / WalletTxToJSON) and wallet/receive.cpp
# (CachedTxGetAmounts).

proc satToBtc(s: Satoshi): float64 =
  float64(int64(s)) / 100_000_000.0

proc recordConfirmations(rpc: RpcServer, rec: WalletTxRecord): int32 =
  ## confirmations = tip - height + 1 for a confirmed tx (Core
  ## GetTxDepthInMainChain), 0 if unconfirmed.
  let currentHeight = if rpc.chainState != nil: rpc.chainState.bestHeight else: 0'i32
  if rec.height > 0 and currentHeight >= rec.height:
    currentHeight - rec.height + 1
  else:
    0'i32

proc recordCategory(rpc: RpcServer, rec: WalletTxRecord): string =
  ## Core ListTransactions receive-leg category for a coinbase: orphan (<1
  ## conf), immature (< COINBASE_MATURITY+1 conf), else generate. Non-coinbase
  ## receive legs are "receive". (Send legs are always "send", handled inline.)
  if not rec.isCoinbase:
    return "receive"
  let confs = rpc.recordConfirmations(rec)
  if confs < 1: "orphan"
  elif confs < (100 + 1): "immature"
  else: "generate"

proc pushTxDescription(rpc: RpcServer, rec: WalletTxRecord, entry: JsonNode) =
  ## Mirror Bitcoin Core WalletTxToJSON: the per-tx description block shared by
  ## listtransactions long entries and gettransaction. Adds confirmations,
  ## generated, block{hash,height,index,time}, txid, time, timereceived.
  let confs = rpc.recordConfirmations(rec)
  entry["confirmations"] = %confs
  if rec.isCoinbase:
    entry["generated"] = %true
  if rec.height > 0:
    entry["blockhash"] = %reverseHex(toHex(array[32, byte](rec.blockHash)))
    entry["blockheight"] = %rec.height
    entry["blockindex"] = %rec.blockIndex
    entry["blocktime"] = %rec.blockTime
  entry["txid"] = %($rec.txid)
  entry["time"] = %rec.time
  entry["timereceived"] = %rec.time

proc buildTxLegs(rpc: RpcServer, rec: WalletTxRecord, fLong: bool,
                 labelFilter: string): seq[JsonNode] =
  ## Build the per-leg JSON entries for one wallet tx, matching Core
  ## ListTransactions: one "send" entry per non-change sent output (amount
  ## negative, negative fee), one receive/generate/immature entry per output
  ## paid to the wallet (amount positive). fLong attaches the tx-description
  ## block (used by listtransactions). labelFilter "*" = no filter.
  result = @[]
  let mainnet = rpc.params.network == Mainnet
  # Fee (positive) = debit - valueOut, only meaningful when the wallet sent.
  let fee = if rec.fromMe: int64(rec.debit) - int64(rec.valueOut) else: 0'i64

  # Sent legs first (Core order).
  if labelFilter == "*":
    for d in rec.details:
      if not d.isSend: continue
      let addrOpt = extractAddressFromScript(d.scriptPubKey, mainnet)
      var entry = newJObject()
      if addrOpt.isSome: entry["address"] = %addrOpt.get()
      entry["category"] = %"send"
      entry["amount"] = %(-satToBtc(d.amount))   # negative for send
      entry["vout"] = %d.vout
      entry["fee"] = %(satToBtc(Satoshi(-fee)))   # negative fee
      if fLong: rpc.pushTxDescription(rec, entry)
      entry["abandoned"] = %false
      result.add(entry)

  # Received legs.
  for d in rec.details:
    if d.isSend or not d.isMine: continue
    let addrOpt = extractAddressFromScript(d.scriptPubKey, mainnet)
    let addressStr = if addrOpt.isSome: addrOpt.get() else: ""
    if labelFilter != "*":
      if addressStr == "": continue
      let lbl = rpc.getTargetWallet().labels.getOrDefault(addressStr, "")
      if lbl != labelFilter: continue
    var entry = newJObject()
    if addrOpt.isSome: entry["address"] = %addrOpt.get()
    # Coinbase receive legs get orphan/immature/generate; else "receive".
    entry["category"] = %rpc.recordCategory(rec)
    entry["amount"] = %satToBtc(d.amount)          # positive for receive
    entry["vout"] = %d.vout
    entry["abandoned"] = %false
    if fLong: rpc.pushTxDescription(rec, entry)
    result.add(entry)

proc handleListTransactions(rpc: RpcServer, params: JsonNode): JsonNode =
  ## List the wallet's most recent transactions, Core-shaped.
  ## Reference: Bitcoin Core wallet/rpc/transactions.cpp listtransactions
  ##
  ## Arguments:
  ## 1. label (string, optional, default="*") - Filter by label (or "*" for all)
  ## 2. count (numeric, optional, default=10) - Number of transactions to return
  ## 3. skip (numeric, optional, default=0) - Number of transactions to skip
  ## 4. include_watchonly (bool, optional, default=true)
  ##
  ## Each entry mirrors Core: {address, category (send/receive/generate/
  ## immature), amount (NEGATIVE for send), vout, fee (negative, send only),
  ## confirmations, generated (coinbase), blockhash, blockheight, blockindex,
  ## blocktime, txid, time, timereceived, abandoned}.
  ##
  ## Backed by the wallet transaction-history ledger (Wallet.txHistory), not
  ## the live UTXO set, so a "send" the wallet made is reported even though its
  ## input UTXOs are gone.

  let w = rpc.getTargetWallet()

  let labelFilter = if params.len >= 1 and params[0].kind == JString: params[0].getStr() else: "*"
  let count = if params.len >= 2: params[1].getInt() else: 10
  let skip = if params.len >= 3: params[2].getInt() else: 0

  if count < 0:
    raise newRpcError(RpcInvalidParams, "count must be non-negative")
  if skip < 0:
    raise newRpcError(RpcInvalidParams, "skip must be non-negative")

  # Flatten every recorded tx into its legs, in scan (first-seen) order. Core
  # appends most-recent last and returns the LAST (count) entries after (skip),
  # i.e. the tail of the time-ordered list. txOrder is oldest-first.
  var allLegs: seq[JsonNode] = @[]
  for txId in w.txOrder:
    if txId notin w.txHistory: continue
    let rec = w.txHistory[txId]
    for leg in rpc.buildTxLegs(rec, fLong = true, labelFilter = labelFilter):
      allLegs.add(leg)

  # Core: return entries [size - count - skip, size - skip), i.e. the tail.
  let total = allLegs.len
  var stop = total - skip
  if stop < 0: stop = 0
  var start = stop - count
  if start < 0: start = 0

  var resultArray = newJArray()
  for i in start ..< stop:
    resultArray.add(allLegs[i])
  resultArray

proc handleGetTransaction(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Get detailed info about an in-wallet transaction, Core-shaped.
  ## Reference: Bitcoin Core wallet/rpc/transactions.cpp gettransaction
  ##
  ## Arguments:
  ## 1. txid (string, required)
  ## 2. include_watchonly (bool, optional)
  ## 3. verbose (bool, optional, default=false)
  ##
  ## Returns {amount, fee (send only, negative), confirmations, generated,
  ## blockhash, blockheight, blockindex, blocktime, txid, time, timereceived,
  ## details:[{address, category, amount, vout, fee}], hex}.

  let w = rpc.getTargetWallet()

  if params.len < 1 or params[0].kind != JString:
    raise newRpcError(RpcInvalidParams, "txid (string) required")
  let txidHex = params[0].getStr()
  if txidHex.len != 64:
    raise newRpcError(RpcInvalidParams, "txid must be 64 hex chars")

  # RPC txids are big-endian display order; reverse to internal byte order.
  var txidBytes: array[32, byte]
  try:
    let raw = parseHexStr(txidHex)
    if raw.len != 32: raise newRpcError(RpcInvalidParams, "txid must be 32 bytes")
    for i in 0 ..< 32:
      txidBytes[31 - i] = byte(raw[i])
  except ValueError:
    raise newRpcError(RpcInvalidParams, "txid is not valid hex")
  let txId = TxId(txidBytes)

  if txId notin w.txHistory:
    raise newRpcError(RpcInvalidAddressOrKey, "Invalid or non-wallet transaction id")
  let rec = w.txHistory[txId]

  # Core gettransaction: nNet = credit - debit; nFee = (fromMe ? valueOut -
  # debit : 0) which is NEGATIVE; top-level amount = nNet - nFee.
  let nNet = int64(rec.credit) - int64(rec.debit)
  let nFeeNeg = if rec.fromMe: int64(rec.valueOut) - int64(rec.debit) else: 0'i64
  let amount = nNet - nFeeNeg

  var entry = newJObject()
  entry["amount"] = %(satToBtc(Satoshi(amount)))
  if rec.fromMe:
    entry["fee"] = %(satToBtc(Satoshi(nFeeNeg)))   # negative
  rpc.pushTxDescription(rec, entry)

  var details = newJArray()
  for leg in rpc.buildTxLegs(rec, fLong = false, labelFilter = "*"):
    details.add(leg)
  entry["details"] = details

  entry["hex"] = %toHex(rec.rawTx)
  entry

# ============================================================================
# Wallet Encryption RPCs
# ============================================================================

proc handleEncryptWallet(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Encrypt the wallet with a passphrase
  ## Reference: Bitcoin Core wallet/rpc/encrypt.cpp encryptwallet
  ##
  ## Arguments:
  ## 1. passphrase (string, required) - The passphrase to encrypt the wallet with
  ##
  ## Returns: Status message

  var w = rpc.getTargetWallet()

  if params.len < 1 or params[0].kind != JString:
    raise newRpcError(RpcInvalidParams, "missing passphrase parameter")

  let passphrase = params[0].getStr()

  if w.isEncrypted:
    raise newRpcError(RpcMiscError, "wallet is already encrypted")

  try:
    discard w.encryptWallet(passphrase)
    %"wallet encrypted successfully"
  except WalletError as e:
    raise newRpcError(RpcMiscError, e.msg)

proc handleWalletPassphrase(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Unlock an encrypted wallet
  ## Reference: Bitcoin Core wallet/rpc/encrypt.cpp walletpassphrase
  ##
  ## Arguments:
  ## 1. passphrase (string, required) - The wallet passphrase
  ## 2. timeout (numeric, required) - Seconds to keep wallet unlocked
  ##
  ## Returns: null on success

  var w = rpc.getTargetWallet()

  if params.len < 2:
    raise newRpcError(RpcInvalidParams, "missing passphrase and/or timeout parameter")

  let passphrase = params[0].getStr()
  let timeout = params[1].getInt()

  if not w.isEncrypted:
    raise newRpcError(RpcMiscError, "wallet is not encrypted")

  try:
    if not w.unlockWallet(passphrase, timeout):
      raise newRpcError(RpcMiscError, "incorrect passphrase")
    newJNull()
  except WalletError as e:
    raise newRpcError(RpcMiscError, e.msg)

proc handleWalletLock(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Lock the wallet
  ## Reference: Bitcoin Core wallet/rpc/encrypt.cpp walletlock
  ##
  ## Returns: null on success

  var w = rpc.getTargetWallet()

  if not w.isEncrypted:
    raise newRpcError(RpcMiscError, "wallet is not encrypted")

  try:
    w.lockWallet()
    newJNull()
  except WalletError as e:
    raise newRpcError(RpcMiscError, e.msg)

proc handleWalletPassphraseChange(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Change the wallet passphrase
  ## Reference: Bitcoin Core wallet/rpc/encrypt.cpp walletpassphrasechange
  ##
  ## Arguments:
  ## 1. oldpassphrase (string, required) - Current passphrase
  ## 2. newpassphrase (string, required) - New passphrase
  ##
  ## Returns: null on success

  var w = rpc.getTargetWallet()

  if params.len < 2:
    raise newRpcError(RpcInvalidParams, "missing oldpassphrase and/or newpassphrase parameter")

  let oldPassphrase = params[0].getStr()
  let newPassphrase = params[1].getStr()

  if not w.isEncrypted:
    raise newRpcError(RpcMiscError, "wallet is not encrypted")

  try:
    if not w.changePassphrase(oldPassphrase, newPassphrase):
      raise newRpcError(RpcMiscError, "incorrect old passphrase")
    newJNull()
  except WalletError as e:
    raise newRpcError(RpcMiscError, e.msg)

# ============================================================================
# Address Label RPCs
# ============================================================================

proc handleSetLabel(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Set a label for an address
  ## Reference: Bitcoin Core wallet/rpc/addresses.cpp setlabel
  ##
  ## Arguments:
  ## 1. address (string, required) - The address to set label for
  ## 2. label (string, required) - The label (empty string removes label)
  ##
  ## Returns: null on success

  var w = rpc.getTargetWallet()

  if params.len < 2:
    raise newRpcError(RpcInvalidParams, "missing address and/or label parameter")

  let address = params[0].getStr()
  let label = params[1].getStr()

  # Validate address
  try:
    discard decodeAddress(address)
  except AddressError:
    raise newRpcError(RpcInvalidAddressOrKey, "invalid address: " & address)

  w.setLabel(address, label)
  rpc.persistTargetWallet()  # DATA-LOSS FIX wa0fq5wtk: label must survive a crash.
  newJNull()

proc handleGetAddressesByLabel(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Get addresses with a label
  ## Reference: Bitcoin Core wallet/rpc/addresses.cpp getaddressesbylabel
  ##
  ## Arguments:
  ## 1. label (string, required) - The label
  ##
  ## Returns: Object with address keys

  if rpc.wallet == nil:
    raise newRpcError(RpcMiscError, "wallet not loaded")

  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing label parameter")

  let label = params[0].getStr()
  let addresses = rpc.wallet.getAddressesByLabel(label)

  var result = newJObject()
  for addr in addresses:
    result[addr] = %*{"purpose": "receive"}

  result

proc handleListLabels(rpc: RpcServer, params: JsonNode): JsonNode =
  ## List all labels
  ## Reference: Bitcoin Core wallet/rpc/addresses.cpp listlabels
  ##
  ## Returns: Array of labels

  if rpc.wallet == nil:
    raise newRpcError(RpcMiscError, "wallet not loaded")

  let labels = rpc.wallet.listLabels()
  var result = newJArray()
  for label in labels:
    result.add(%label)
  result

# =============================================================================
# Descriptor RPCs
# =============================================================================

proc handleGetDescriptorInfo(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Analyze a descriptor
  ## Reference: Bitcoin Core rpc/output_script.cpp getdescriptorinfo
  ##
  ## Arguments:
  ## 1. descriptor (string, required) - The descriptor
  ##
  ## Returns: Object with descriptor analysis

  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing descriptor parameter")

  let descriptorStr = params[0].getStr()
  let mainnet = rpc.params.network == Mainnet
  let regtest = rpc.params.network == Regtest

  try:
    let info = getDescriptorInfo(descriptorStr, mainnet, regtest)
    %*{
      "descriptor": info.descriptor,
      "checksum": info.checksum,
      "isrange": info.isRange,
      "issolvable": info.isSolvable,
      "hasprivatekeys": info.hasPrivateKeys
    }
  except DescriptorError as e:
    raise newRpcError(RpcInvalidParams, "invalid descriptor: " & e.msg)

proc handleListDescriptors*(rpc: RpcServer, params: JsonNode): JsonNode =
  ## listdescriptors ( private )
  ##
  ## List all descriptors present in the wallet, in Bitcoin Core's shape.
  ## Reference: bitcoin-core/src/wallet/rpc/backup.cpp listdescriptors.
  ##
  ## Response (private=false default):
  ##   { wallet_name, descriptors: [ { desc (WITH #checksum), timestamp,
  ##     active, internal (active only), range + next/next_index
  ##     (ranged active... emitted for ranged), ... } ] }
  ##   sorted by descriptor string.
  ##
  ## nimrod's descriptor store is the set of watch-only descriptors registered
  ## via importdescriptors (Wallet.watchedScripts, persisted in the
  ## watched_descriptors sqlite table). Those imports are watch-only and are
  ## NOT installed as active address-generating SPKMs, so `active` is false for
  ## every one (matching Core's importdescriptors default `active=false`,
  ## backup.cpp:172-192). `internal` is therefore omitted for all (Core emits
  ## it only for active descriptors). For a ranged descriptor we report
  ## `range = [range_start, range_end-1]` and `next`/`next_index = next_index`,
  ## which for an imported ranged descriptor is range_start (0) by default
  ## (backup.cpp:185 `next_index = range_start`). Our stored `rangeEnd` is the
  ## INCLUSIVE last index (Core's range_end-1), so range = [0, rangeEnd].
  ##
  ## Exported (`*`) so unit tests can call it directly.

  let priv = params.len >= 1 and params[0].kind == JBool and params[0].getBool()

  let w = rpc.getTargetWallet()

  # private descriptors are unsupported for watch-only wallets in Core
  # (backup.cpp:500-502). nimrod's importdescriptors store is watch-only.
  if priv and w.privateKeysDisabled:
    raise newRpcError(RpcWalletError,
      "Can't get private descriptor string for watch-only wallets")

  # Resolve the wallet name for the wallet_name field, same lookup chain as
  # getwalletinfo.
  var walletName = "default"
  if rpc.walletManager != nil and rpc.currentWalletName != "":
    walletName = rpc.currentWalletName
  elif rpc.walletManager != nil:
    let lwOpt = rpc.walletManager.getDefaultWallet()
    if lwOpt.isSome:
      walletName = lwOpt.get().name

  # One emitted entry per UNIQUE descriptor string. Prefer the persisted
  # watched_descriptors rows when a sqlite handle is available — they carry the
  # authoritative `rangeEnd`, which the per-script in-memory table does not
  # retain. Fall back to the in-memory watchedScripts table (re-deriving
  # isRange by parsing; range/next default to 0) when there is no DB.
  type DescEntry = object
    descriptor: string
    timestamp: int64
    rangeEnd: int
    isRange: bool
  var entries = initOrderedTable[string, DescEntry]()

  let lw = rpc.getTargetLoadedWallet()
  var usedDb = false
  if lw != nil and lw.db != nil and lw.db.isOpen:
    try:
      for row in lw.db.getWatchedDescriptors():
        usedDb = true
        var ranged = false
        try:
          let payload = splitDescriptorChecksum(row.descriptor, requireChecksum = false)
          ranged = parseDescriptor(payload).node.isRange()
        except CatchableError:
          ranged = row.rangeEnd > 0
        entries[row.descriptor] = DescEntry(
          descriptor: row.descriptor,
          timestamp: row.timestamp,
          rangeEnd: row.rangeEnd,
          isRange: ranged)
    except CatchableError:
      usedDb = false

  if not usedDb:
    for _, ws in w.watchedScripts:
      if entries.hasKey(ws.descriptor):
        continue
      var ranged = false
      try:
        let payload = splitDescriptorChecksum(ws.descriptor, requireChecksum = false)
        ranged = parseDescriptor(payload).node.isRange()
      except CatchableError:
        ranged = false
      entries[ws.descriptor] = DescEntry(
        descriptor: ws.descriptor,
        timestamp: ws.timestamp,
        rangeEnd: 0,
        isRange: ranged)

  # Sort by descriptor string (Core sorts the result array, backup.cpp:541-543).
  var keys = newSeq[string]()
  for k in entries.keys:
    keys.add(k)
  keys.sort()

  var descriptors = newJArray()
  for k in keys:
    let e = entries[k]
    var obj = newJObject()
    obj["desc"] = %e.descriptor   # already carries the trailing #checksum
    obj["timestamp"] = %e.timestamp
    obj["active"] = %false        # watch-only imports are never active here
    # `internal` is emitted only for active descriptors -> omitted.
    if e.isRange:
      # next_index defaults to range_start (0) for imported descriptors.
      let nextIndex = 0
      var rng = newJArray()
      rng.add(%0)
      rng.add(%e.rangeEnd)        # inclusive end (Core's range_end-1)
      obj["range"] = rng
      obj["next"] = %nextIndex
      obj["next_index"] = %nextIndex
    descriptors.add(obj)

  result = newJObject()
  result["wallet_name"] = %walletName
  result["descriptors"] = descriptors

proc handleDeriveAddresses(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Derive addresses from a descriptor
  ## Reference: Bitcoin Core rpc/output_script.cpp deriveaddresses
  ##
  ## Arguments:
  ## 1. descriptor (string, required) - The descriptor
  ## 2. range (int or array, optional) - For ranged descriptors: index or [start, end]
  ##
  ## Returns: Array of derived addresses

  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing descriptor parameter")

  let descriptorStr = params[0].getStr()

  # Determine network from server params
  let mainnet = rpc.params.network == Mainnet

  try:
    let desc = parseDescriptor(descriptorStr)

    if desc.node.isRange():
      # Ranged descriptor - need range parameter
      var start = 0
      var count = 1

      if params.len >= 2:
        if params[1].kind == JInt:
          # Single index
          start = params[1].getInt()
          count = 1
        elif params[1].kind == JArray and params[1].len == 2:
          # [start, end] range
          start = params[1][0].getInt()
          let endIdx = params[1][1].getInt()
          count = endIdx - start + 1
          if count <= 0:
            raise newRpcError(RpcInvalidParams, "end must be >= start")
          if count > 10000:
            raise newRpcError(RpcInvalidParams, "range too large (max 10000)")
        else:
          raise newRpcError(RpcInvalidParams, "range must be int or [start, end]")

      let addresses = deriveAddresses(desc, start, count, mainnet)
      var result = newJArray()
      for addr in addresses:
        result.add(%addr)
      result
    else:
      # Non-ranged descriptor
      if params.len >= 2:
        raise newRpcError(RpcInvalidParams, "range not allowed for non-ranged descriptor")

      let addresses = deriveAddresses(desc, 0, 1, mainnet)
      var result = newJArray()
      for addr in addresses:
        result.add(%addr)
      result
  except DescriptorError as e:
    raise newRpcError(RpcInvalidParams, "invalid descriptor: " & e.msg)

proc univalueTypeName(kind: JsonNodeKind): string =
  ## UniValue type names exactly as Core prints them in RPC_TYPE_ERROR
  ## messages (univalue VType names).
  case kind
  of JNull: "null"
  of JBool: "bool"
  of JInt, JFloat: "number"
  of JString: "string"
  of JArray: "array"
  of JObject: "object"

proc parseImportRange(v: JsonNode): tuple[lo, hi: int] =
  ## Parse importdescriptors' "range" value: n -> [0, n]; [begin, end].
  ## Core ParseDescriptorRange / rpc/util.cpp (-8 messages verbatim).
  if v.kind == JInt:
    let n = v.getInt()
    if n < 0:
      raise newRpcError(RpcInvalidParameter, "Range should be greater or equal than 0")
    return (0, n)
  if v.kind == JArray and v.len == 2 and v[0].kind == JInt and v[1].kind == JInt:
    let lo = v[0].getInt()
    let hi = v[1].getInt()
    if lo < 0:
      raise newRpcError(RpcInvalidParameter, "Range should be greater or equal than 0")
    if hi < lo:
      raise newRpcError(RpcInvalidParameter,
        "Range specified as [begin,end] must not have begin after end")
    if hi - lo >= 10000:
      raise newRpcError(RpcInvalidParameter, "Range is too large")
    return (lo, hi)
  raise newRpcError(RpcInvalidParameter,
    "Range must be specified as integer or as [begin,end]")

proc findRescanStartHeight(rpc: RpcServer, targetTime: int64): int32 {.gcsafe.} =
  ## First active-chain height whose header time >= targetTime. The caller
  ## passes lowest_timestamp - TIMESTAMP_WINDOW (7200s), mirroring
  ## CWallet::RescanFromTime (bitcoin-core/src/wallet/wallet.cpp:1827-1848):
  ## funds received up to 2 hours BEFORE the stated timestamp are credited.
  ## Returns tip+1 when no block qualifies (the rescan becomes a no-op).
  let tip = rpc.chainState.bestHeight
  var h = 0'i32
  while h <= tip:
    let hashOpt = rpc.chainState.db.getBlockHashByHeight(h)
    if hashOpt.isSome:
      let idxOpt = rpc.chainState.db.getBlockIndex(hashOpt.get())
      if idxOpt.isSome and int64(idxOpt.get().header.timestamp) >= targetTime:
        return h
    inc h
  tip + 1

proc importDescriptorWifKeys(w: var Wallet, node: DescriptorNode) =
  ## For a WIF-bearing single-key descriptor imported into a wallet with
  ## private keys ENABLED, register the private key in the keystore too (so
  ## the imported coins are spendable, like Core's descriptor SPKM holding
  ## the key). Watch registration still happens separately; this only adds
  ## the signing path.
  case node.kind
  of DKPk, DKPkh, DKWpkh, DKCombo, DKRawTr:
    if node.key.kind == KPConstWIF:
      discard w.importPrivateKey(node.key.privateKey, compressed = true)
  of DKSh, DKWsh:
    importDescriptorWifKeys(w, node.sub)
  else:
    discard

proc handleImportDescriptors*(rpc: RpcServer, params: JsonNode): JsonNode =
  ## importdescriptors "requests"
  ##
  ## Import output descriptors as WATCH-ONLY scripts (or, on a wallet with
  ## private keys enabled, with their WIF keys) and synchronously rescan the
  ## chain so pre-import funds are credited. Replaces the 2026-05-05 honest
  ## -4 refusal gate (cross-impl lying-RPC audit) with the real thing.
  ##
  ## Core-contract behaviors implemented (bitcoin-core/src/wallet/rpc/
  ## backup.cpp importdescriptors / ProcessDescriptorImport):
  ##   * Per-element results — one {success[, error]} object per request
  ##     element, array parallel to the input; an element failure NEVER
  ##     aborts the batch (backup.cpp:141-300 try/catch per element).
  ##   * EXCEPTION: a bad/missing "timestamp" in ANY element aborts the whole
  ##     call with a top-level -3 (GetImportTimestamp is called OUTSIDE the
  ##     per-element try, backup.cpp:388-392 + 127-139).
  ##   * Checksums are REQUIRED (Parse(..., require_checksum=true),
  ##     backup.cpp:158); any parse/checksum failure surfaces per-element as
  ##     -5 with Core's CheckChecksum message strings (descriptor.cpp:
  ##     2838-2869), e.g. "Missing checksum".
  ##   * disable_private_keys gates, both directions, per-element -4
  ##     (backup.cpp:224-226 and 259-262).
  ##   * timestamp: numeric (clamped >= 1) or "now" (= chain-tip MTP,
  ##     backup.cpp:376,385,390). After >=1 successful element the chain is
  ##     rescanned SYNCHRONOUSLY from the first block with header time >=
  ##     min(timestamps) - TIMESTAMP_WINDOW (7200s) — Core's
  ##     RescanFromTime(lowest_timestamp, update=true) blocks too.
  ##
  ## Exported (`*`) so tests can call it directly.
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing requests parameter")
  if params[0].kind != JArray:
    raise newRpcError(RpcInvalidParams, "requests must be an array")

  var w = rpc.getTargetWallet()
  let lw = rpc.getTargetLoadedWallet()  # nil => no sqlite persistence
  if rpc.chainState == nil:
    raise newRpcError(RpcMiscError, "no chain state")

  let requests = params[0]
  let tipHeight = rpc.chainState.bestHeight
  # "now" = chain-tip median-time-past (Core binds `now` via
  # FoundBlock().mtpTime at backup.cpp:385).
  let nowMtp =
    if tipHeight >= 0: int64(getMtpForHeight(rpc.chainState.db, tipHeight))
    else: getTime().toUnix()

  # Phase 1 — resolve EVERY element's timestamp before importing anything.
  # Core's GetImportTimestamp runs outside the per-element try, so a single
  # malformed timestamp is a top-level RPC_TYPE_ERROR (-3) for the whole call.
  var timestamps = newSeq[int64](requests.len)
  for i in 0 ..< requests.len:
    let el = requests[i]
    if el.kind != JObject or not el.hasKey("timestamp"):
      raise newRpcError(RpcTypeError, "Missing required timestamp field for key")
    let ts = el["timestamp"]
    case ts.kind
    of JInt:
      timestamps[i] = ts.getBiggestInt()
    of JFloat:
      timestamps[i] = int64(ts.getFloat())
    of JString:
      if ts.getStr() == "now":
        timestamps[i] = nowMtp
      else:
        raise newRpcError(RpcTypeError,
          "Expected number or \"now\" timestamp value for key. got type string")
    else:
      raise newRpcError(RpcTypeError,
        "Expected number or \"now\" timestamp value for key. got type " &
        univalueTypeName(ts.kind))

  # Phase 2 — per-element import. Failures are per-element error objects.
  var results = newJArray()
  var anySuccess = false
  var lowestTs = int64.high
  for i in 0 ..< requests.len:
    let el = requests[i]
    var elemRes = newJObject()
    try:
      # minimum_timestamp = 1: timestamp 0 means scan-whole-chain
      # (backup.cpp:376,390 max(GetImportTimestamp, 1)).
      let ts = max(timestamps[i], 1'i64)

      if not el.hasKey("desc") or el["desc"].kind != JString:
        raise newRpcError(RpcInvalidParameter, "Descriptor not found.")
      let descStr = el["desc"].getStr()
      let label =
        if el.hasKey("label") and el["label"].kind == JString: el["label"].getStr()
        else: ""

      # BIP-380 checksum gate, require-mode, then grammar parse. Core funnels
      # both failure kinds into RPC_INVALID_ADDRESS_OR_KEY (-5)
      # (backup.cpp:159-161).
      var payload: string
      var desc: Descriptor
      try:
        payload = splitDescriptorChecksum(descStr, requireChecksum = true)
        desc = parseDescriptor(payload)
      except DescriptorError as e:
        raise newRpcError(RpcInvalidAddressOrKey, e.msg)
      except CatchableError as e:
        # decodeAddress/parse internals can raise non-DescriptorError types;
        # Core maps every Parse failure to -5.
        raise newRpcError(RpcInvalidAddressOrKey, e.msg)
      let canonical = payload & "#" & computeDescriptorChecksum(payload)

      # Range validation (Core backup.cpp:166-178, -8 messages).
      var rangeEnd = 0
      if desc.node.isRange():
        if not el.hasKey("range"):
          raise newRpcError(RpcInvalidParameter,
            "Descriptor is ranged, please specify the range")
        let (_, hi) = parseImportRange(el["range"])
        rangeEnd = hi
      elif el.hasKey("range"):
        raise newRpcError(RpcInvalidParameter,
          "Range should not be specified for an un-ranged descriptor")

      # disable_private_keys gates, both directions (backup.cpp:224-226,
      # 259-262; RPC_WALLET_ERROR -4).
      let hasPriv = descriptorHasPrivateKeys(desc)
      if w.privateKeysDisabled and hasPriv:
        raise newRpcError(RpcWalletError,
          "Cannot import private keys to a wallet with private keys disabled")
      if (not w.privateKeysDisabled) and (not hasPriv):
        raise newRpcError(RpcWalletError,
          "Cannot import descriptor without private keys to a wallet with " &
          "private keys enabled")

      # Register the watch scripts (and, on an enabled wallet, the WIF keys
      # so the coins are spendable).
      applyWatchedDescriptor(w, desc, canonical, label, ts, rangeEnd,
                             rpc.params.network == Mainnet)
      if hasPriv and not w.privateKeysDisabled:
        importDescriptorWifKeys(w, desc.node)

      # Persist the descriptor row so the watch survives a wallet reload.
      if lw != nil and lw.db != nil:
        try:
          lw.db.saveWatchedDescriptor(canonical, label, ts, rangeEnd)
        except CatchableError:
          discard  # in-memory import still stands; reload-safety degraded

      anySuccess = true
      if ts < lowestTs:
        lowestTs = ts
      elemRes["success"] = %true
    except RpcError as e:
      elemRes = newJObject()
      elemRes["success"] = %false
      elemRes["error"] = %*{"code": e.code, "message": e.msg}
    except CatchableError as e:
      elemRes = newJObject()
      elemRes["success"] = %false
      elemRes["error"] = %*{"code": RpcMiscError, "message": e.msg}
    results.add(elemRes)

  # Phase 3 — synchronous rescan iff >=1 element succeeded (backup.cpp:
  # 399-410), from the first block with time >= lowest - TIMESTAMP_WINDOW.
  # rescanWalletRange runs scanBlockForWallet over the range — the same
  # recognition path as block-connect — so pre-import funds are credited
  # into balance/listunspent before this RPC returns (Core blocks too).
  if anySuccess:
    if tipHeight >= 0:
      var startHeight = 0'i32
      if lowestTs > 1:
        startHeight = rpc.findRescanStartHeight(lowestTs - 7200)
      if startHeight <= tipHeight:
        rpc.rescanWalletRange(w, startHeight, tipHeight)
    rpc.persistTargetWallet()

  results

proc handleGetAddressInfo*(rpc: RpcServer, params: JsonNode): JsonNode =
  ## getaddressinfo "address"
  ##
  ## Wallet-relative information about an address. Field order mirrors
  ## Core's runtime emission order (bitcoin-core/src/wallet/rpc/
  ## addresses.cpp:441-508): address, scriptPubKey, ismine, solvable,
  ## desc (only when solvable), parent_desc (only for descriptor-backed
  ## scripts — here: the imported watch descriptor with checksum),
  ## iswatchonly (deprecated, ALWAYS false — addresses.cpp:478), then the
  ## DescribeWalletAddress fields (isscript/iswitness/witness_*), ischange,
  ## timestamp (when known), labels last (empty array allowed). JObject is
  ## an OrderedTable, so insertion order is response order.
  ##
  ## Invalid address -> -5 (addresses.cpp:431-439).
  let w = rpc.getTargetWallet()

  if params.len < 1 or params[0].kind != JString:
    raise newRpcError(RpcInvalidParams, "address required")
  let addrStr = params[0].getStr()

  var parsedAddr: Address
  try:
    parsedAddr = decodeAddress(addrStr)
  except CatchableError:
    raise newRpcError(RpcInvalidAddressOrKey, "Invalid address")

  let spk = scriptPubKeyForAddress(parsedAddr)
  let keyOpt = w.findKeyForScript(spk)
  let watched = w.isWatchedScript(spk)
  let ismine = keyOpt.isSome or watched

  # solvable: key-backed addresses always; watched scripts iff their source
  # descriptor is solvable (addr()/raw() watches are NOT — Core infers no
  # signing provider for them).
  var solvable = keyOpt.isSome
  var watchEntry: WatchedScript
  if watched:
    watchEntry = w.watchedScripts[spk]
    if not solvable:
      try:
        solvable = parseDescriptor(watchEntry.descriptor).node.isSolvable()
      except CatchableError:
        solvable = false

  result = newJObject()
  result["address"] = %addrStr
  result["scriptPubKey"] = %toHex(spk)
  result["ismine"] = %ismine
  result["solvable"] = %solvable
  if solvable and watched:
    # The canonical imported descriptor doubles as desc for non-ranged
    # single-script watches (Core: inferred per-address descriptor).
    result["desc"] = %watchEntry.descriptor
  if watched:
    result["parent_desc"] = %watchEntry.descriptor
  # Deprecated, always false since the legacy-watchonly removal (Core v29+).
  result["iswatchonly"] = %false
  let isWitness = parsedAddr.kind in {P2WPKH, P2WSH, P2TR}
  result["isscript"] = %(parsedAddr.kind in {P2SH, P2WSH, P2TR})
  result["iswitness"] = %isWitness
  if isWitness:
    result["witness_version"] = %(if parsedAddr.kind == P2TR: 1 else: 0)
    var prog: string
    case parsedAddr.kind
    of P2WPKH: prog = toHex(parsedAddr.wpkh)
    of P2WSH: prog = toHex(parsedAddr.wsh)
    of P2TR: prog = toHex(parsedAddr.taprootKey)
    else: prog = ""
    result["witness_program"] = %prog
  result["ischange"] = %(keyOpt.isSome and keyOpt.get().path.contains("/1/"))
  if watched and watchEntry.timestamp > 0:
    result["timestamp"] = %watchEntry.timestamp
  var labels = newJArray()
  if addrStr in w.labels and w.labels[addrStr].len > 0:
    labels.add(%w.labels[addrStr])
  result["labels"] = labels

# ============================================================================
# PSBT RPCs
# ============================================================================

proc handleCreatePsbt(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Create an unsigned PSBT from inputs and outputs
  ## Reference: Bitcoin Core rpc/rawtransaction.cpp createpsbt
  ##
  ## Arguments:
  ## 1. inputs (array, required) - Array of input objects:
  ##    - txid (string): The transaction id
  ##    - vout (int): The output number
  ##    - sequence (int, optional): The sequence number
  ## 2. outputs (array, required) - Array of output objects:
  ##    - {address: amount} for address outputs
  ##    - {"data": hex} for OP_RETURN outputs
  ## 3. locktime (int, optional, default=0) - Raw locktime
  ## 4. replaceable (bool, optional, default=false) - Marks inputs RBF-able
  ##
  ## Returns: Base64-encoded PSBT string

  if params.len < 2:
    raise newRpcError(RpcInvalidParams, "missing required parameters: inputs, outputs")

  # Parse outputs first because Core's AddInputs needs nLockTime already set
  # to choose 0xfffffffe vs 0xffffffff in the !rbf branch — but locktime in
  # nimrod params is index 2, so parse it before walking inputs.
  if params[0].kind != JArray:
    raise newRpcError(RpcInvalidParams, "inputs must be an array")
  if params[1].kind != JArray:
    raise newRpcError(RpcInvalidParams, "outputs must be an array")

  # Parse locktime
  var locktime = 0'u32
  if params.len >= 3 and params[2].kind != JNull:
    locktime = uint32(params[2].getInt())

  # Parse replaceable flag (BIP-125 opt-in RBF).
  # FIX-70 / W120 BUG-2 Core parity: AddInputs() in
  # bitcoin-core/src/rpc/rawtransaction_util.cpp uses
  #   rbf.value_or(true)  // default TRUE when caller omits replaceable
  # so the wallet default for createpsbt is RBF-signaling
  # (MAX_BIP125_RBF_SEQUENCE = 0xfffffffd). Previously nimrod treated the
  # absence of `replaceable` as `false`, which silently emitted
  # 0xffffffff (SEQUENCE_FINAL) — non-RBF, non-locktime-enforcing. Core's
  # `CWallet::m_signal_rbf` has defaulted to true since v23.
  var replaceable = true  # Core default (DEFAULT_WALLET_RBF / rbf.value_or(true))
  if params.len >= 4 and params[3].kind != JNull:
    replaceable = params[3].getBool()

  # Per-input default sequence — mirrors Core's AddInputs():
  #   rbf  → MAX_BIP125_RBF_SEQUENCE   = 0xfffffffd
  #   !rbf && locktime → MAX_SEQUENCE_NONFINAL = 0xfffffffe
  #   !rbf && !locktime → SEQUENCE_FINAL = 0xffffffff
  # Explicit "sequence" field on a per-input basis always overrides.
  let defaultSequence: uint32 =
    if replaceable: 0xfffffffd'u32
    elif locktime > 0: 0xfffffffe'u32
    else: 0xffffffff'u32

  var txInputs: seq[TxIn]
  for inputObj in params[0]:
    if inputObj.kind != JObject:
      raise newRpcError(RpcInvalidParams, "each input must be an object")

    if not inputObj.hasKey("txid") or not inputObj.hasKey("vout"):
      raise newRpcError(RpcInvalidParams, "input missing txid or vout")

    let txidHex = inputObj["txid"].getStr()
    if txidHex.len != 64:
      raise newRpcError(RpcInvalidAddressOrKey, "invalid txid length")

    let txid = parseTxId(txidHex)
    let vout = uint32(inputObj["vout"].getInt())

    var sequence = defaultSequence
    if inputObj.hasKey("sequence"):
      sequence = uint32(inputObj["sequence"].getInt())

    txInputs.add(TxIn(
      prevOut: OutPoint(txid: txid, vout: vout),
      scriptSig: @[],  # Empty for PSBT
      sequence: sequence
    ))

  # Parse outputs
  var txOutputs: seq[TxOut]
  for outputObj in params[1]:
    if outputObj.kind != JObject:
      raise newRpcError(RpcInvalidParams, "each output must be an object")

    # Check for data (OP_RETURN) output
    if outputObj.hasKey("data"):
      let dataHex = outputObj["data"].getStr()
      let data = hexToBytes(dataHex)
      # Build OP_RETURN script: OP_RETURN <data>
      var script: seq[byte]
      script.add(0x6a)  # OP_RETURN
      if data.len <= 75:
        script.add(byte(data.len))
      elif data.len <= 255:
        script.add(0x4c)  # OP_PUSHDATA1
        script.add(byte(data.len))
      else:
        raise newRpcError(RpcInvalidParams, "OP_RETURN data too long")
      script.add(data)
      txOutputs.add(TxOut(value: Satoshi(0), scriptPubKey: script))
    else:
      # Address output: {address: amount}
      for key, val in outputObj:
        if key == "data":
          continue
        let address = key
        let amountBtc = val.getFloat()
        let amountSat = Satoshi(int64(amountBtc * 100_000_000))

        try:
          let parsedAddr = decodeAddress(address)
          let scriptPubKey = scriptPubKeyForAddress(parsedAddr)
          txOutputs.add(TxOut(value: amountSat, scriptPubKey: scriptPubKey))
        except AddressError as e:
          raise newRpcError(RpcInvalidAddressOrKey, "invalid address: " & e.msg)

  # Create unsigned transaction
  let tx = Transaction(
    version: 2'i32,
    inputs: txInputs,
    outputs: txOutputs,
    witnesses: @[],
    lockTime: locktime
  )

  # Create PSBT
  let psbtObj = createPsbt(tx)

  # Return base64-encoded
  %psbtObj.toBase64()

# ============================================================================
# signrawtransactionwithwallet
# ============================================================================
#
# Reference: Bitcoin Core src/wallet/rpc/spend.cpp::signrawtransactionwithwallet
#            and our cross-impl gold standard:
#            camlcoin/lib/rpc.ml::handle_signrawtransactionwithkey (line 2743+)
#
# This is the wallet-holder's "I have UTXOs, please sign" path. It bridges the
# previously orphaned `createrawtransaction`/`createpsbt` ↔ `sendrawtransaction`
# pipeline: prior to this dispatch, a wallet-holder had no way to go from
# "have wallet UTXOs" to "broadcast tx" (Cat H wallet audit, 2026-05-06).
#
# Signing strategy:
# - For each input, locate the prevout via (a) the optional `prevtxs` arg,
#   (b) the wallet's own UTXO table, or (c) the chainstate UTXO set.
# - Find the matching key in the wallet via findKeyForScript on the
#   scriptPubKey of the prevout.
# - For P2WPKH, sign with BIP143 (calls into the now-public
#   wallet.signInputP2WPKH).
# - Other script types are reported as un-signable in the per-input `errors`
#   array (Core parity: failures are non-fatal, the partially-signed tx is
#   still returned).
proc handleSignRawTransactionWithWallet(rpc: RpcServer,
                                         params: JsonNode): JsonNode =
  ## signrawtransactionwithwallet "hexstring" ( [{...}, ...] sighashtype )
  ## Sign inputs of a raw transaction using the loaded wallet's keys.
  ##
  ## Arguments:
  ## 1. hexstring   (string, required) — hex-encoded raw transaction
  ## 2. prevtxs     (array,  optional) — array of {txid, vout, scriptPubKey,
  ##                                     amount} prevout descriptors
  ## 3. sighashtype (string, optional, default "DEFAULT") — sighash flag
  ##
  ## Returns: { "hex": str, "complete": bool, "errors"?: array }
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing hexstring parameter")

  let txHex = params[0].getStr()

  var w = rpc.getTargetWallet()

  if w.isEncrypted and w.isLocked:
    raise newRpcError(RpcMiscError,
      "wallet is locked; use walletpassphrase to unlock")

  # Parse the raw transaction
  var tx: Transaction
  try:
    let txBytes = hexToBytes(txHex)
    tx = deserializeTransaction(txBytes)
  except CatchableError as e:
    raise newRpcError(RpcInvalidParams, "TX decode failed: " & e.msg)

  # Ensure witnesses array exists for each input (deserialize may have
  # produced an empty `witnesses` if the tx was non-segwit on the wire).
  if tx.witnesses.len < tx.inputs.len:
    let oldLen = tx.witnesses.len
    tx.witnesses.setLen(tx.inputs.len)
    for i in oldLen ..< tx.inputs.len:
      tx.witnesses[i] = @[]

  # Build a prevout lookup table from the optional `prevtxs` arg.
  # Keys: (txid_internal, vout) → TxOut
  #
  # W29-E: also collect optional `redeemScript` (P2SH wraps) and
  # `witnessScript` (P2WSH inner scripts) so the signer can route to
  # the wrapped / native-segwit-v0 paths.
  var prevTable = initTable[tuple[txid: TxId, vout: uint32], TxOut]()
  var redeemTable = initTable[tuple[txid: TxId, vout: uint32], seq[byte]]()
  var witnessTable = initTable[tuple[txid: TxId, vout: uint32], seq[byte]]()
  if params.len >= 2 and params[1].kind == JArray:
    for prev in params[1]:
      if prev.kind != JObject:
        continue
      if not (prev.hasKey("txid") and prev.hasKey("vout") and
              prev.hasKey("scriptPubKey")):
        continue
      try:
        let txidHex = prev["txid"].getStr()
        if txidHex.len != 64: continue
        let txid = parseTxId(txidHex)
        let vout = uint32(prev["vout"].getInt())
        let spk = hexToBytes(prev["scriptPubKey"].getStr())
        var amount = Satoshi(0)
        if prev.hasKey("amount"):
          let v = prev["amount"]
          if v.kind == JFloat:
            amount = Satoshi(int64(v.getFloat() * 100_000_000.0))
          elif v.kind == JInt:
            amount = Satoshi(int64(v.getInt()) * 100_000_000)
        prevTable[(txid, vout)] = TxOut(value: amount, scriptPubKey: spk)
        if prev.hasKey("redeemScript") and prev["redeemScript"].kind == JString:
          let rs = prev["redeemScript"].getStr()
          if rs.len > 0:
            redeemTable[(txid, vout)] = hexToBytes(rs)
        if prev.hasKey("witnessScript") and prev["witnessScript"].kind == JString:
          let ws = prev["witnessScript"].getStr()
          if ws.len > 0:
            witnessTable[(txid, vout)] = hexToBytes(ws)
      except CatchableError:
        continue

  # Sign each input independently. Failures append to `errors` but do not
  # abort the loop (Core parity).
  var errors = newJArray()
  var signedCount = 0

  for i, txin in tx.inputs:
    let key = (txin.prevOut.txid, txin.prevOut.vout)

    # Resolve the prevout: prevtxs → wallet utxos → chainstate UTXO set.
    var prevOut: TxOut
    var found = false
    if key in prevTable:
      prevOut = prevTable[key]
      found = true
    elif txin.prevOut in w.utxos:
      prevOut = w.utxos[txin.prevOut].output
      found = true
    elif rpc.chainState != nil:
      let utxoOpt = rpc.chainState.getUtxo(txin.prevOut)
      if utxoOpt.isSome:
        prevOut = utxoOpt.get().output
        found = true

    if not found:
      errors.add(%*{
        "txid": reverseHex(toHex(array[32, byte](txin.prevOut.txid))),
        "vout": txin.prevOut.vout,
        "scriptSig": "",
        "sequence": txin.sequence,
        "error": "Input not found or already spent"
      })
      continue

    # Look up the signing key for this prevout's scriptPubKey.
    let keyOpt = w.findKeyForScript(prevOut.scriptPubKey)
    if keyOpt.isNone:
      errors.add(%*{
        "txid": reverseHex(toHex(array[32, byte](txin.prevOut.txid))),
        "vout": txin.prevOut.vout,
        "scriptSig": "",
        "sequence": txin.sequence,
        "error": "Unable to sign input, invalid stack size (possibly missing key)"
      })
      continue

    let dkey = keyOpt.get()
    let spk = prevOut.scriptPubKey

    # ------------------------------------------------------------------
    # W29-E: extended dispatch over all 5 standard wallet spend types.
    #   1. P2WPKH      — native v0 witness (existing)
    #   2. P2PKH       — legacy (W29-E)
    #   3. P2SH-P2WPKH — wrapped, redeemScript supplied (W29-E)
    #   4. P2WSH       — native v0, witnessScript supplied (W29-E, multisig)
    #   5. P2SH-P2WSH  — wrapped, witnessScript supplied (W29-E, multisig)
    # P2TR remains un-wired (BIP-371 PSBT taproot fields out of scope).
    # ------------------------------------------------------------------

    # P2WPKH: 0x00 0x14 <20-byte-hash>
    if spk.len == 22 and spk[0] == 0x00 and spk[1] == 0x14:
      try:
        signInputP2WPKH(tx, i, dkey.extKey.key, dkey.extKey.publicKey,
                        prevOut.value)
        inc signedCount
      except CatchableError as e:
        errors.add(%*{
          "txid": reverseHex(toHex(array[32, byte](txin.prevOut.txid))),
          "vout": txin.prevOut.vout,
          "scriptSig": "",
          "sequence": txin.sequence,
          "error": "Signing failed: " & e.msg
        })

    # P2PKH (legacy BIP44):
    #   OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    elif spk.len == 25 and spk[0] == 0x76 and spk[1] == 0xa9 and
         spk[2] == 0x14 and spk[23] == 0x88 and spk[24] == 0xac:
      try:
        signInputP2PKH(tx, i, dkey.extKey.key, dkey.extKey.publicKey)
        inc signedCount
      except CatchableError as e:
        errors.add(%*{
          "txid": reverseHex(toHex(array[32, byte](txin.prevOut.txid))),
          "vout": txin.prevOut.vout,
          "scriptSig": "",
          "sequence": txin.sequence,
          "error": "Signing failed: " & e.msg
        })

    # P2SH (bare wrap): OP_HASH160 <20> OP_EQUAL.
    # We must distinguish P2SH-P2WPKH from P2SH-P2WSH using the supplied
    # redeemScript shape (caller responsibility per BIP-174).
    elif spk.len == 23 and spk[0] == 0xa9 and spk[1] == 0x14 and
         spk[22] == 0x87:
      let rsKey = (txin.prevOut.txid, txin.prevOut.vout)
      if rsKey notin redeemTable:
        errors.add(%*{
          "txid": reverseHex(toHex(array[32, byte](txin.prevOut.txid))),
          "vout": txin.prevOut.vout,
          "scriptSig": "",
          "sequence": txin.sequence,
          "error": "P2SH input requires redeemScript in prevtxs"
        })
      else:
        let redeemScript = redeemTable[rsKey]
        # W31: every P2SH dispatch path MUST first prove the supplied
        # redeemScript actually hashes to the prevout's script-hash, or a
        # forged redeemScript turns the wallet into a signing oracle.
        # Reference: bitcoin-core/src/script/sign.cpp::ProduceSignature
        # (TX_SCRIPTHASH branch) + camlcoin/lib/wallet.ml:1262.
        if not verifyP2SHCommitment(redeemScript, prevOut.scriptPubKey):
          errors.add(%*{
            "txid": reverseHex(toHex(array[32, byte](txin.prevOut.txid))),
            "vout": txin.prevOut.vout,
            "scriptSig": "",
            "sequence": txin.sequence,
            "error": "redeemScript hash160 does not match scriptPubKey"
          })
        # P2SH-P2WPKH: redeemScript = 22 bytes, 0x00 0x14 <hash160>
        elif redeemScript.len == 22 and redeemScript[0] == 0x00 and
             redeemScript[1] == 0x14:
          try:
            signInputP2SHP2WPKH(tx, i, dkey.extKey.key, dkey.extKey.publicKey,
                                prevOut.value)
            inc signedCount
          except CatchableError as e:
            errors.add(%*{
              "txid": reverseHex(toHex(array[32, byte](txin.prevOut.txid))),
              "vout": txin.prevOut.vout,
              "scriptSig": "",
              "sequence": txin.sequence,
              "error": "Signing failed: " & e.msg
            })
        # P2SH-P2WSH: redeemScript = 34 bytes, 0x00 0x20 <sha256>
        elif redeemScript.len == 34 and redeemScript[0] == 0x00 and
             redeemScript[1] == 0x20:
          if rsKey notin witnessTable:
            errors.add(%*{
              "txid": reverseHex(toHex(array[32, byte](txin.prevOut.txid))),
              "vout": txin.prevOut.vout,
              "scriptSig": "",
              "sequence": txin.sequence,
              "error": "P2SH-P2WSH requires witnessScript in prevtxs"
            })
          # W31: also verify witnessScript commits to redeemScript[2..33]
          # (sha256 inner check).  Without this an attacker could forge a
          # witnessScript whose redeemScript happens to be wallet-recognized
          # but whose inner sighash is attacker-controlled.
          elif not verifyP2SHWrappedP2WSHCommitment(witnessTable[rsKey],
                                                    redeemScript):
            errors.add(%*{
              "txid": reverseHex(toHex(array[32, byte](txin.prevOut.txid))),
              "vout": txin.prevOut.vout,
              "scriptSig": "",
              "sequence": txin.sequence,
              "error": "witnessScript sha256 does not match redeemScript"
            })
          else:
            try:
              # Wallet-only single-key signing: use the matched derived key.
              # Multisig P2SH-P2WSH with multiple wallet keys is out of scope
              # for this dispatch (caller would use PSBT).
              signInputP2SHP2WSH(tx, i, [dkey.extKey.key],
                                 witnessTable[rsKey],
                                 prevOut.value,
                                 isMultisig = false)
              inc signedCount
            except CatchableError as e:
              errors.add(%*{
                "txid": reverseHex(toHex(array[32, byte](txin.prevOut.txid))),
                "vout": txin.prevOut.vout,
                "scriptSig": "",
                "sequence": txin.sequence,
                "error": "Signing failed: " & e.msg
              })
        else:
          errors.add(%*{
            "txid": reverseHex(toHex(array[32, byte](txin.prevOut.txid))),
            "vout": txin.prevOut.vout,
            "scriptSig": "",
            "sequence": txin.sequence,
            "error": "Unsupported P2SH redeemScript shape"
          })

    # Native P2WSH: 0x00 0x20 <32-byte-sha256>
    elif spk.len == 34 and spk[0] == 0x00 and spk[1] == 0x20:
      let wsKey = (txin.prevOut.txid, txin.prevOut.vout)
      if wsKey notin witnessTable:
        errors.add(%*{
          "txid": reverseHex(toHex(array[32, byte](txin.prevOut.txid))),
          "vout": txin.prevOut.vout,
          "scriptSig": "",
          "sequence": txin.sequence,
          "error": "P2WSH input requires witnessScript in prevtxs"
        })
      # W31: prove `sha256(witnessScript) == spk[2..33]` before signing.
      # Reference: bitcoin-core/src/script/sign.cpp (TX_WITNESS_V0_SCRIPTHASH
      # branch of SignStep). Without this check a forged witnessScript would
      # be hashed under a wallet sighash and signed.
      elif not verifyP2WSHCommitment(witnessTable[wsKey], spk):
        errors.add(%*{
          "txid": reverseHex(toHex(array[32, byte](txin.prevOut.txid))),
          "vout": txin.prevOut.vout,
          "scriptSig": "",
          "sequence": txin.sequence,
          "error": "witnessScript sha256 does not match scriptPubKey"
        })
      else:
        try:
          # Single-key wallet-owned P2WSH (rare but well-defined).
          signInputP2WSH(tx, i, [dkey.extKey.key], witnessTable[wsKey],
                         prevOut.value, isMultisig = false)
          inc signedCount
        except CatchableError as e:
          errors.add(%*{
            "txid": reverseHex(toHex(array[32, byte](txin.prevOut.txid))),
            "vout": txin.prevOut.vout,
            "scriptSig": "",
            "sequence": txin.sequence,
            "error": "Signing failed: " & e.msg
          })

    elif spk.len == 34 and spk[0] == 0x51 and spk[1] == 0x20:
      # P2TR — Schnorr signing not yet wired; report as un-signable.
      errors.add(%*{
        "txid": reverseHex(toHex(array[32, byte](txin.prevOut.txid))),
        "vout": txin.prevOut.vout,
        "scriptSig": "",
        "sequence": txin.sequence,
        "error": "P2TR signing not yet implemented in this wallet"
      })
    else:
      errors.add(%*{
        "txid": reverseHex(toHex(array[32, byte](txin.prevOut.txid))),
        "vout": txin.prevOut.vout,
        "scriptSig": "",
        "sequence": txin.sequence,
        "error": "Unsupported script type (only P2WPKH wallet signing supported)"
      })

  # Re-serialize the (possibly partially-signed) tx.
  let signedHex = toHex(serialize(tx, includeWitness = true))
  let complete = (errors.len == 0) and (signedCount == tx.inputs.len)

  result = %*{
    "hex": signedHex,
    "complete": complete
  }
  if errors.len > 0:
    result["errors"] = errors

# ============================================================================
# walletcreatefundedpsbt
# ============================================================================
#
# Reference: bitcoin-core/src/wallet/rpc/spend.cpp::walletcreatefundedpsbt
#
# Creator + Updater roles: build an unsigned PSBT, automatically funding it
# from the wallet's UTXOs if no inputs are pre-specified. We do NOT sign.
# Returns { psbt, fee, changepos } (Core-compatible shape).
proc handleWalletCreateFundedPsbt(rpc: RpcServer,
                                   params: JsonNode): JsonNode =
  ## walletcreatefundedpsbt [inputs] [{output, ...}] ( locktime options bip32derivs )
  ##
  ## Arguments:
  ## 1. inputs   (array, optional) — pre-selected inputs ({txid, vout, sequence})
  ## 2. outputs  (array, required) — [{address: amount}, {"data": hex}]
  ## 3. locktime (int,   optional, default=0)
  ## 4. options  (object, optional) — {feeRate, fee_rate, replaceable,
  ##                                   changeAddress, subtractFeeFromOutputs}
  ## 5. bip32derivs (bool, optional, default=true) — currently best-effort
  ##
  ## Returns: { psbt: base64, fee: BTC, changepos: int }
  if params.len < 2:
    raise newRpcError(RpcInvalidParams,
      "missing required parameters: inputs, outputs")

  var w = rpc.getTargetWallet()

  if params[0].kind != JArray:
    raise newRpcError(RpcInvalidParams, "inputs must be an array")
  if params[1].kind != JArray:
    raise newRpcError(RpcInvalidParams, "outputs must be an array")

  # ---- locktime (parsed early so AddInputs-equivalent can pick the right
  # default sequence for the !rbf branch) ----
  var locktimeEarly = 0'u32
  if params.len >= 3 and params[2].kind != JNull:
    locktimeEarly = uint32(params[2].getInt())

  # ---- Resolve replaceable upfront so per-input default sequence matches
  # Core's AddInputs() (rbf=MAX_BIP125_RBF_SEQUENCE 0xfffffffd, !rbf+lt=
  # MAX_SEQUENCE_NONFINAL 0xfffffffe, !rbf+!lt=SEQUENCE_FINAL 0xffffffff).
  # Core walletcreatefundedpsbt: rbf = options.replaceable ?? m_signal_rbf,
  # and DEFAULT_WALLET_RBF=true. We mirror that — replaceable defaults true.
  var replaceableEarly = true
  if params.len >= 4 and params[3].kind == JObject:
    let optsEarly = params[3]
    if optsEarly.hasKey("replaceable") and optsEarly["replaceable"].kind == JBool:
      replaceableEarly = optsEarly["replaceable"].getBool()

  let defaultPreInputSequence: uint32 =
    if replaceableEarly: 0xfffffffd'u32
    elif locktimeEarly > 0: 0xfffffffe'u32
    else: 0xffffffff'u32

  # ---- Parse pre-selected inputs (may be empty → auto-fund) ----
  var preInputs: seq[TxIn]
  for inputObj in params[0]:
    if inputObj.kind != JObject:
      raise newRpcError(RpcInvalidParams, "each input must be an object")
    if not inputObj.hasKey("txid") or not inputObj.hasKey("vout"):
      raise newRpcError(RpcInvalidParams, "input missing txid or vout")
    let txidHex = inputObj["txid"].getStr()
    if txidHex.len != 64:
      raise newRpcError(RpcInvalidAddressOrKey, "invalid txid length")
    let txid = parseTxId(txidHex)
    let vout = uint32(inputObj["vout"].getInt())
    # FIX-70 / W120 BUG-2: default to BIP-125-signaling sequence unless
    # caller explicitly disabled replaceable or set a non-default sequence.
    # Previously this defaulted to 0xffffffff and relied on the post-loop
    # upgrade — that upgrade was correct for the common case but flipped
    # 0xffffffff → 0xfffffffd even when caller asked for !rbf + locktime,
    # silently dropping into BIP-125 territory.
    var sequence = defaultPreInputSequence
    if inputObj.hasKey("sequence"):
      sequence = uint32(inputObj["sequence"].getInt())
    preInputs.add(TxIn(
      prevOut: OutPoint(txid: txid, vout: vout),
      scriptSig: @[],
      sequence: sequence
    ))

  # ---- Parse outputs (and remember requested order for changepos) ----
  var txOutputs: seq[TxOut]
  for outputObj in params[1]:
    if outputObj.kind != JObject:
      raise newRpcError(RpcInvalidParams, "each output must be an object")

    if outputObj.hasKey("data"):
      let dataHex = outputObj["data"].getStr()
      let data = hexToBytes(dataHex)
      var script: seq[byte]
      script.add(0x6a)  # OP_RETURN
      if data.len <= 75:
        script.add(byte(data.len))
      elif data.len <= 255:
        script.add(0x4c)
        script.add(byte(data.len))
      else:
        raise newRpcError(RpcInvalidParams, "OP_RETURN data too long")
      script.add(data)
      txOutputs.add(TxOut(value: Satoshi(0), scriptPubKey: script))
    else:
      for k, v in outputObj:
        if k == "data":
          continue
        let amountBtc = v.getFloat()
        let amountSat = Satoshi(int64(amountBtc * 100_000_000))
        try:
          let parsedAddr = decodeAddress(k)
          let spk = scriptPubKeyForAddress(parsedAddr)
          txOutputs.add(TxOut(value: amountSat, scriptPubKey: spk))
        except AddressError as e:
          raise newRpcError(RpcInvalidAddressOrKey,
            "invalid address: " & e.msg)

  # ---- locktime / replaceable (already parsed early for pre-input default
  # sequence; re-bind to the names used by the rest of the body) ----
  let locktime = locktimeEarly
  let replaceable = replaceableEarly

  # ---- remaining options ----
  var feeRate = 0.0  # 0 means "use estimator"
  var changeAddrOverride = ""
  if params.len >= 4 and params[3].kind == JObject:
    let opts = params[3]
    if opts.hasKey("fee_rate"):
      # sat/vB
      feeRate = opts["fee_rate"].getFloat()
    elif opts.hasKey("feeRate"):
      # BTC/kvB → sat/vB
      feeRate = opts["feeRate"].getFloat() * 100_000_000.0 / 1000.0
    if opts.hasKey("changeAddress"):
      changeAddrOverride = opts["changeAddress"].getStr()

  if feeRate <= 0.0:
    if rpc.feeEstimator != nil:
      feeRate = rpc.feeEstimator.estimateFee(6)
    else:
      feeRate = FallbackFeeRate

  # ---- Build the unsigned, funded transaction ----
  var fundedTx: Transaction
  var totalIn = Satoshi(0)
  var totalOut = Satoshi(0)
  for o in txOutputs:
    totalOut = totalOut + o.value

  var changePos = -1
  var changeOutputCount = 0  # 0 or 1

  if preInputs.len > 0:
    # Caller-specified inputs: build tx as-is. Fee = sum(inputs) - sum(outputs).
    # We trust the caller has correctly chosen inputs; we don't add change.
    # (Core's walletcreatefundedpsbt with explicit inputs and add_inputs=false
    #  similarly does no extra coin selection — fee inferred from delta.)
    fundedTx = Transaction(
      version: 2'i32,
      inputs: preInputs,
      outputs: txOutputs,
      witnesses: newSeq[seq[seq[byte]]](preInputs.len),
      lockTime: locktime
    )
    # Resolve totalIn from wallet utxos / chainstate
    for inp in preInputs:
      if inp.prevOut in w.utxos:
        totalIn = totalIn + w.utxos[inp.prevOut].output.value
      elif rpc.chainState != nil:
        let u = rpc.chainState.getUtxo(inp.prevOut)
        if u.isSome:
          totalIn = totalIn + u.get().output.value
  else:
    # Auto-fund using wallet.createTransaction. This adds a change output
    # (when needed) and selects coins.
    try:
      fundedTx = w.createTransaction(txOutputs, feeRate)
    except WalletError as e:
      raise newRpcError(RpcWalletError, e.msg)
    except CoinSelectionError as e:
      raise newRpcError(RpcWalletError, e.msg)
    # Sum totalIn from selected inputs
    for inp in fundedTx.inputs:
      if inp.prevOut in w.utxos:
        totalIn = totalIn + w.utxos[inp.prevOut].output.value
    # Detect the change output (if any). createTransaction appends change at
    # the end of the outputs vector. changepos = index of that extra output;
    # -1 if no change was needed.
    if fundedTx.outputs.len > txOutputs.len:
      changePos = txOutputs.len  # the one appended by createTransaction
      changeOutputCount = 1

  # ---- Apply locktime/replaceable RBF semantics ----
  # FIX-70 / W120 BUG-2 Core parity: mirror AddInputs() — for any input that
  # the wallet/caller left at the "unset" sentinel (0xffffffff), pick the
  # appropriate default. For the auto-fund path, wallet.createTransaction
  # already emits 0xfffffffd; if caller explicitly passed replaceable=false,
  # walk RBF-signaling inputs back to the Core default (0xfffffffe if
  # locktime>0, else 0xffffffff). Pre-set non-final sequences are left alone.
  fundedTx.lockTime = locktime
  if replaceable:
    for i in 0 ..< fundedTx.inputs.len:
      if fundedTx.inputs[i].sequence == 0xffffffff'u32:
        fundedTx.inputs[i].sequence = 0xfffffffd'u32
  else:
    # caller explicitly opted out of RBF — undo wallet.createTransaction's
    # default 0xfffffffd so the on-the-wire tx truly does not signal opt-in.
    let nonRbfDefault: uint32 =
      if locktime > 0: 0xfffffffe'u32 else: 0xffffffff'u32
    for i in 0 ..< fundedTx.inputs.len:
      if fundedTx.inputs[i].sequence == 0xfffffffd'u32:
        fundedTx.inputs[i].sequence = nonRbfDefault

  # ---- Optional changeAddress override (rebuild change output) ----
  if changeOutputCount == 1 and changeAddrOverride.len > 0:
    try:
      let parsed = decodeAddress(changeAddrOverride)
      let spk = scriptPubKeyForAddress(parsed)
      fundedTx.outputs[changePos].scriptPubKey = spk
    except AddressError as e:
      raise newRpcError(RpcInvalidAddressOrKey,
        "invalid changeAddress: " & e.msg)

  # ---- Recompute fee from inputs/outputs ----
  var sumOuts = Satoshi(0)
  for o in fundedTx.outputs:
    sumOuts = sumOuts + o.value
  let fee = int64(totalIn) - int64(sumOuts)

  # ---- Strip witnesses; PSBT carries an unsigned tx by spec ----
  fundedTx.witnesses = newSeq[seq[seq[byte]]](fundedTx.inputs.len)
  for i in 0 ..< fundedTx.witnesses.len:
    fundedTx.witnesses[i] = @[]

  # ---- Build PSBT and populate witnessUtxo for each input we know about ----
  var psbtObj = createPsbt(fundedTx)
  for i, inp in fundedTx.inputs:
    var prev: TxOut
    var have = false
    if inp.prevOut in w.utxos:
      prev = w.utxos[inp.prevOut].output
      have = true
    elif rpc.chainState != nil:
      let u = rpc.chainState.getUtxo(inp.prevOut)
      if u.isSome:
        prev = u.get().output
        have = true
    if have:
      try:
        psbtObj.updateInput(i, prev, isWitness = true)
      except CatchableError:
        discard  # best-effort

  %*{
    "psbt": psbtObj.toBase64(),
    "fee": float64(fee) / 100_000_000.0,
    "changepos": changePos
  }

# ============================================================================
# walletprocesspsbt
# ============================================================================
#
# Reference: bitcoin-core/src/wallet/rpc/spend.cpp::walletprocesspsbt (1569)
#            → CWallet::FillPSBT → FinalizeAndExtractPSBT.
#
# Updater + Signer (+ Finalizer + Extractor) roles. Given a base64 PSBT, fill
# in the UTXO data the wallet knows (witness_utxo / non_witness_utxo + scripts),
# SIGN every input the wallet holds a key for, optionally finalize, and return
# { psbt, complete (+ hex when complete) }.
#
# Signing strategy (⭐ REUSE — no fresh sighash/ECDSA):
#   We do NOT reimplement BIP-143 / legacy sighashing. Instead we materialise
#   the PSBT's unsigned tx into a mutable Transaction, drive the EXACT same
#   signInputP2WPKH / signInputP2PKH / signInputP2SHP2WPKH engine that
#   signrawtransactionwithwallet uses (computeSighashSegwitV0 /
#   computeSighashLegacy + secp256k1.sign + DER), then lift the produced
#   (pubkey -> DER-sig) pair back onto the PSBT input as a BIP-174 partial
#   signature. The existing finalizePsbt() then assembles the final
#   scriptSig / witness exactly as finalizepsbt does. This keeps a single
#   signing code path across signrawtransactionwithwallet, walletcreatefundedpsbt
#   (creator) and walletprocesspsbt (signer).
proc parseWalletSighashType(s: string): uint32 =
  ## Map a Core sighash string to the wire hashType byte. "DEFAULT" maps to
  ## SIGHASH_ALL for the non-taproot scripts this wallet signs (Core treats
  ## DEFAULT as ALL for ECDSA inputs). Raises RpcInvalidParams on a bad value.
  ## Values are the canonical Bitcoin sighash flags (SIGHASH_ALL=0x01,
  ## NONE=0x02, SINGLE=0x03, ANYONECANPAY=0x80) — kept as literals here to
  ## avoid importing script/interpreter into the RPC module.
  const
    shAll = 0x01'u32
    shNone = 0x02'u32
    shSingle = 0x03'u32
    shAcp = 0x80'u32
  case s
  of "", "DEFAULT", "ALL": shAll
  of "NONE": shNone
  of "SINGLE": shSingle
  of "ALL|ANYONECANPAY": shAll or shAcp
  of "NONE|ANYONECANPAY": shNone or shAcp
  of "SINGLE|ANYONECANPAY": shSingle or shAcp
  else:
    raise newRpcError(RpcInvalidParams,
      "'" & s & "' is not a valid sighash parameter.")

proc handleWalletProcessPsbt(rpc: RpcServer, params: JsonNode): JsonNode =
  ## walletprocesspsbt "psbt" ( sign sighashtype bip32derivs finalize )
  ##
  ## Arguments:
  ## 1. psbt        (string, required) — base64-encoded PSBT
  ## 2. sign        (bool,   optional, default=true)
  ## 3. sighashtype (string, optional, default "ALL")
  ## 4. bip32derivs (bool,   optional, default=true) — best-effort
  ## 5. finalize    (bool,   optional, default=true)
  ##
  ## Returns: { psbt: base64, complete: bool (, hex: str when complete) }
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing psbt parameter")

  var w = rpc.getTargetWallet()

  let sign = if params.len >= 2 and params[1].kind == JBool:
               params[1].getBool() else: true
  let sighashStr = if params.len >= 3 and params[2].kind == JString:
                     params[2].getStr() else: "ALL"
  let hashType = parseWalletSighashType(sighashStr)
  let finalize = if params.len >= 5 and params[4].kind == JBool:
                   params[4].getBool() else: true

  if sign and w.isEncrypted and w.isLocked:
    raise newRpcError(RpcMiscError,
      "wallet is locked; use walletpassphrase to unlock")

  # ---- Decode ----
  var psbtObj: Psbt
  try:
    psbtObj = fromBase64(params[0].getStr())
  except PsbtError as e:
    raise newRpcError(RpcDeserializationError, "TX decode failed: " & e.msg)
  except CatchableError as e:
    raise newRpcError(RpcDeserializationError, "TX decode failed: " & e.msg)

  if psbtObj.tx.isNone:
    raise newRpcError(RpcDeserializationError,
      "PSBT is missing its unsigned transaction")
  let unsignedTx = psbtObj.tx.get()

  # Helper: resolve a prevout TxOut for an input, preferring the PSBT's own
  # witness_utxo / non_witness_utxo, then wallet UTXOs, then chainstate.
  proc resolvePrevOut(idx: int): Option[TxOut] =
    if psbtObj.inputs[idx].witnessUtxo.isSome:
      return psbtObj.inputs[idx].witnessUtxo
    if psbtObj.inputs[idx].nonWitnessUtxo.isSome:
      let prevTx = psbtObj.inputs[idx].nonWitnessUtxo.get()
      let vout = int(unsignedTx.inputs[idx].prevOut.vout)
      if vout < prevTx.outputs.len:
        return some(prevTx.outputs[vout])
    let op = unsignedTx.inputs[idx].prevOut
    if op in w.utxos:
      return some(w.utxos[op].output)
    if rpc.chainState != nil:
      let u = rpc.chainState.getUtxo(op)
      if u.isSome:
        return some(u.get().output)
    none(TxOut)

  # ------------------------------------------------------------------
  # Updater role: fill UTXO data for every input the wallet can resolve.
  # witness_utxo for segwit (v0/v1) scripts, non_witness_utxo otherwise.
  # ------------------------------------------------------------------
  for i in 0 ..< psbtObj.inputs.len:
    if psbtObj.inputs[i].witnessUtxo.isSome or
       psbtObj.inputs[i].nonWitnessUtxo.isSome:
      continue
    let prevOpt = resolvePrevOut(i)
    if prevOpt.isNone:
      continue
    let prev = prevOpt.get()
    # We carry the resolved prevout as witness_utxo. For segwit inputs this is
    # the canonical field; for legacy inputs the wallet UTXO store only holds
    # the TxOut (not the full funding tx), so we stash the same TxOut here so
    # the finalizer can recover the prevout scriptPubKey (finalizePsbtInput
    # reads witnessUtxo.scriptPubKey for the legacy P2PKH branch too). A later
    # Updater pass carrying the full funding tx may upgrade this to
    # non_witness_utxo via updateInputWithTx.
    psbtObj.inputs[i].witnessUtxo = some(prev)

  # ------------------------------------------------------------------
  # Signer role: materialise the unsigned tx, drive the shared signInput*
  # engine, lift the produced (pubkey -> DER sig) back as a partial sig.
  # ------------------------------------------------------------------
  if sign:
    for i in 0 ..< psbtObj.inputs.len:
      # Skip inputs that are already finalized.
      if psbtObj.inputs[i].isSigned():
        continue

      let prevOpt = resolvePrevOut(i)
      if prevOpt.isNone:
        continue
      let prev = prevOpt.get()
      let spk = prev.scriptPubKey

      let keyOpt = w.findKeyForScript(spk)
      if keyOpt.isNone:
        continue  # not our key; leave for another signer (Core parity)
      let dkey = keyOpt.get()

      # Per-input sighash override: honour PSBT_IN_SIGHASH_TYPE when present,
      # else the RPC-level sighashtype.
      let inHashType =
        if psbtObj.inputs[i].sighashType.isSome:
          uint32(psbtObj.inputs[i].sighashType.get())
        else:
          hashType

      # Build a single-input scratch tx around this input so the existing
      # signers (which sign tx.inputs[idx] in place) operate on a faithful
      # copy. We sign over the FULL unsigned tx (all inputs/outputs) so the
      # BIP-143 / legacy sighash commits to the real transaction.
      var scratch = unsignedTx
      scratch.witnesses = newSeq[seq[seq[byte]]](scratch.inputs.len)
      for k in 0 ..< scratch.witnesses.len:
        scratch.witnesses[k] = @[]

      var signedOk = false
      var derSig: seq[byte]
      var pub: seq[byte] = @(dkey.extKey.publicKey)
      var redeemForPsbt: seq[byte] = @[]

      try:
        if spk.len == 22 and spk[0] == 0x00 and spk[1] == 0x14:
          # P2WPKH
          signInputP2WPKH(scratch, i, dkey.extKey.key, dkey.extKey.publicKey,
                          prev.value, inHashType)
          # witness = [derSig, pubkey]
          if scratch.witnesses[i].len == 2:
            derSig = scratch.witnesses[i][0]
            signedOk = true
        elif spk.len == 25 and spk[0] == 0x76 and spk[1] == 0xa9 and
             spk[2] == 0x14 and spk[23] == 0x88 and spk[24] == 0xac:
          # P2PKH (legacy)
          signInputP2PKH(scratch, i, dkey.extKey.key, dkey.extKey.publicKey,
                         inHashType)
          # scriptSig = <len><derSig><len><pubkey>
          let ss = scratch.inputs[i].scriptSig
          if ss.len > 0:
            let sigLen = int(ss[0])
            if 1 + sigLen <= ss.len:
              derSig = ss[1 .. sigLen]
              signedOk = true
        elif spk.len == 23 and spk[0] == 0xa9 and spk[1] == 0x14 and
             spk[22] == 0x87:
          # P2SH-P2WPKH (wrapped segwit). The wallet derives the redeemScript
          # OP_0 <hash160(pubkey)> itself; verify it commits to the prevout.
          let wpkh = hash160(dkey.extKey.publicKey)
          var redeem = @[0x00'u8, 0x14]
          redeem.add(@wpkh)
          if verifyP2SHCommitment(redeem, spk):
            signInputP2SHP2WPKH(scratch, i, dkey.extKey.key,
                                dkey.extKey.publicKey, prev.value, inHashType)
            if scratch.witnesses[i].len == 2:
              derSig = scratch.witnesses[i][0]
              redeemForPsbt = redeem
              signedOk = true
        else:
          # P2WSH / P2SH-P2WSH / bare multisig / P2TR: requires
          # witnessScript / taproot data not derivable from a single wallet
          # key here. Leave unsigned (Core parity: non-fatal, partial result).
          discard
      except CatchableError:
        signedOk = false

      if signedOk and derSig.len > 0:
        psbtObj.addPartialSig(i, pub, derSig)
        if redeemForPsbt.len > 0 and psbtObj.inputs[i].redeemScript.len == 0:
          psbtObj.inputs[i].redeemScript = redeemForPsbt
        # Record the sighash type we signed with (BIP-174 PSBT_IN_SIGHASH_TYPE).
        if psbtObj.inputs[i].sighashType.isNone:
          psbtObj.inputs[i].sighashType = some(int32(inHashType))

  # ------------------------------------------------------------------
  # Finalizer role (optional): assemble final scriptSig / witness from the
  # collected partial sigs via the shared finalizePsbt engine.
  # ------------------------------------------------------------------
  var complete = false
  if finalize:
    complete = finalizePsbt(psbtObj)
  else:
    # Without finalize, "complete" reflects whether every input is already
    # ready to finalize (Core: FillPSBT reports complete iff all inputs are
    # finalizable). Probe with the analyzer's readiness check.
    complete = psbtObj.inputs.len > 0
    for i in 0 ..< psbtObj.inputs.len:
      if not (psbtObj.inputs[i].isSigned() or
              isInputReadyToFinalize(psbtObj.inputs[i])):
        complete = false
        break

  result = newJObject()
  result["psbt"] = %psbtObj.toBase64()
  result["complete"] = %complete

  # Core emits the finalized network tx hex whenever complete is true.
  if complete:
    let txOpt = extractTransaction(psbtObj)
    if txOpt.isSome:
      result["hex"] = %toHex(serialize(txOpt.get(), includeWitness = true))

# ============================================================================
# createrawtransaction
# ============================================================================
#
# Reference: bitcoin-core/src/rpc/rawtransaction.cpp::createrawtransaction (377)
#            → rawtransaction_util.cpp::ConstructTransaction / AddInputs /
#              AddOutputs / ParseOutputs.
#
# Build an UNSIGNED raw tx from (inputs, outputs, locktime=0, replaceable=false)
# and return its hex. REUSES the same machinery as walletcreatefundedpsbt's
# input/output parsing: parseTxId (txid validation), decodeAddress +
# scriptPubKeyForAddress (address → scriptPubKey), the OP_RETURN script builder,
# and serialize() (the shared tx serializer, also used by sendrawtransaction /
# decoderawtransaction). No coin selection and no signing — outputs are emitted
# verbatim, witnesses stay empty so serialize() emits the legacy (no segwit
# marker) encoding, exactly like Core's EncodeHexTx(CTransaction(rawTx)).

proc fixedPointSatFromString(s: string): int64 =
  ## Mirror util/strencodings.cpp ParseFixedPoint with decimals=8 and the
  ## MoneyRange check from AmountFromValue, operating on the canonical decimal
  ## string. Raises RpcTypeError (-3) like Core on a malformed/out-of-range
  ## amount. Fixed-point only — no binary float — so the byte output is exact.
  var str = s.strip()
  if str.len == 0:
    raise newRpcError(RpcTypeError, "Invalid amount")
  var neg = false
  var i = 0
  if str[0] in {'+', '-'}:
    neg = str[0] == '-'
    i = 1
  var whole: int64 = 0
  var sawDigit = false
  while i < str.len and str[i] in {'0'..'9'}:
    whole = whole * 10 + int64(ord(str[i]) - ord('0'))
    sawDigit = true
    inc i
    if whole > 21_000_000'i64 + 1:        # short-circuit overflow guard
      raise newRpcError(RpcTypeError, "Amount out of range")
  var frac: int64 = 0
  var fracDigits = 0
  if i < str.len and str[i] == '.':
    inc i
    while i < str.len and str[i] in {'0'..'9'}:
      if fracDigits >= 8:
        raise newRpcError(RpcTypeError, "Invalid amount")
      frac = frac * 10 + int64(ord(str[i]) - ord('0'))
      inc fracDigits
      sawDigit = true
      inc i
  if i != str.len or not sawDigit:
    raise newRpcError(RpcTypeError, "Invalid amount")
  # Scale fractional part up to 8 digits.
  while fracDigits < 8:
    frac = frac * 10
    inc fracDigits
  var sats = whole * 100_000_000'i64 + frac
  if neg: sats = -sats
  # MoneyRange: 0 <= amount <= MAX_MONEY (21e6 * COIN).
  if sats < 0 or sats > int64(MaxMoney):
    raise newRpcError(RpcTypeError, "Amount out of range")
  sats

proc amountFromValueSat(v: JsonNode): int64 =
  ## Core rpc/util.cpp AmountFromValue: BTC amount → satoshis.
  ## - JString / JInt: parsed as fixed-point from the verbatim text (exact).
  ## - JFloat: Nim's std/json already lost the source text to a float64, so
  ##   round to the nearest satoshi (round-half-away-from-zero). This matches
  ##   Core for any amount representable in <=8 decimals — e.g. 0.001 → 100000
  ##   — which is the createrawtransaction contract (decimals=8). The result is
  ##   then re-validated through the same fixed-point MoneyRange path.
  case v.kind
  of JString:
    fixedPointSatFromString(v.getStr())
  of JInt:
    fixedPointSatFromString($v.getInt())
  of JFloat:
    let f = v.getFloat()
    let scaled = f * 100_000_000.0
    let sats = int64(if scaled >= 0: scaled + 0.5 else: scaled - 0.5)
    if sats < 0 or sats > int64(MaxMoney):
      raise newRpcError(RpcTypeError, "Amount out of range")
    sats
  else:
    raise newRpcError(RpcTypeError, "Amount is not a number or string")

proc handleCreateRawTransaction(rpc: RpcServer, params: JsonNode): JsonNode =
  ## createrawtransaction [{"txid","vout","sequence"?},...] {"address":amount,...}
  ##                      ( locktime replaceable )
  ##
  ## Returns the hex string of an unsigned raw transaction.
  if params.len < 2:
    raise newRpcError(RpcInvalidParams,
      "createrawtransaction requires inputs and outputs")
  if params[0].kind != JArray:
    raise newRpcError(RpcTypeError, "Expected type array for inputs")

  # ---- locktime (param 2, default 0) ----
  var locktime: uint32 = 0
  if params.len >= 3 and params[2].kind != JNull:
    if params[2].kind != JInt:
      raise newRpcError(RpcTypeError, "Expected type number for locktime")
    let lt = params[2].getInt()
    if lt < 0 or lt > 0xffffffff'i64:
      raise newRpcError(RpcInvalidParameter,
        "Invalid parameter, locktime out of range")
    locktime = uint32(lt)

  # ---- replaceable (param 3) ----
  # Core ConstructTransaction receives rbf as std::optional<bool>:
  # createrawtransaction passes std::nullopt when the arg is ABSENT and the
  # explicit bool when present (rawtransaction.cpp:398-401). AddInputs then
  # picks the input sequence (rawtransaction_util.cpp:49-55):
  #   rbf.value_or(true)              → MAX_BIP125_RBF_SEQUENCE  0xfffffffd
  #   else if nLockTime != 0          → MAX_SEQUENCE_NONFINAL    0xfffffffe
  #   else                            → SEQUENCE_FINAL           0xffffffff
  # value_or(true) means BOTH "arg absent" AND "replaceable=true" → RBF default.
  # (rustoshi FIX-70 / W120 BUG-3 documents the same Core default.)
  var rbf = true  # std::nullopt → value_or(true)
  if params.len >= 4 and params[3].kind != JNull:
    if params[3].kind != JBool:
      raise newRpcError(RpcTypeError, "Expected type bool for replaceable")
    rbf = params[3].getBool()
  let defaultSequence: uint32 =
    if rbf: 0xfffffffd'u32
    elif locktime != 0: 0xfffffffe'u32
    else: 0xffffffff'u32

  # ---- inputs ----
  var inputs: seq[TxIn]
  for inputObj in params[0]:
    if inputObj.kind != JObject:
      raise newRpcError(RpcTypeError, "Expected type object for input")
    if not inputObj.hasKey("txid") or inputObj["txid"].kind != JString:
      raise newRpcError(RpcInvalidParameter, "Invalid parameter, missing txid")
    let txidHex = inputObj["txid"].getStr()
    validateHashV(txidHex, "txid")  # Core ParseHashV: -8 on non-64-hex txid (BEFORE parseTxId, which would otherwise crash on a short/invalid string)
    let txid = parseTxId(txidHex)
    if not inputObj.hasKey("vout") or inputObj["vout"].kind != JInt:
      raise newRpcError(RpcInvalidParameter,
        "Invalid parameter, missing vout key")
    let nOutput = inputObj["vout"].getInt()
    if nOutput < 0:
      raise newRpcError(RpcInvalidParameter,
        "Invalid parameter, vout cannot be negative")
    var sequence = defaultSequence
    if inputObj.hasKey("sequence") and inputObj["sequence"].kind != JNull:
      if inputObj["sequence"].kind != JInt:
        raise newRpcError(RpcTypeError, "Expected type number for sequence")
      let seqNr = inputObj["sequence"].getInt()
      if seqNr < 0 or seqNr > 0xffffffff'i64:
        raise newRpcError(RpcInvalidParameter,
          "Invalid parameter, sequence number is out of range")
      sequence = uint32(seqNr)
    inputs.add(TxIn(
      prevOut: OutPoint(txid: txid, vout: uint32(nOutput)),
      scriptSig: @[],
      sequence: sequence
    ))

  # ---- outputs ----
  # Core NormalizeOutputs (rawtransaction_util.cpp:74-99): accept EITHER an
  # object {address:amount,...,"data":hex} OR an array of single-key objects
  # [{address:amount},{"data":hex}], translating the array form into an ordered
  # (key,value) list. We normalize both into `normOutputs` so the downstream
  # ParseOutputs logic (dup detection, OP_RETURN, address→spk) is identical.
  var normOutputs: seq[(string, JsonNode)]
  case params[1].kind
  of JObject:
    for k, v in params[1]:
      normOutputs.add((k, v))
  of JArray:
    for entry in params[1]:
      if entry.kind != JObject:
        raise newRpcError(RpcInvalidParameter,
          "Invalid parameter, key-value pair not an object as expected")
      if entry.len != 1:
        raise newRpcError(RpcInvalidParameter,
          "Invalid parameter, key-value pair must contain exactly one key")
      for k, v in entry:
        normOutputs.add((k, v))
  else:
    raise newRpcError(RpcTypeError,
      "Expected type object or array for outputs")

  var outputs: seq[TxOut]
  var seenData = false
  var seenAddrs = initHashSet[string]()
  for (k, v) in normOutputs:
    if k == "data":
      if seenData:
        raise newRpcError(RpcInvalidParameter,
          "Invalid parameter, duplicate key: data")
      seenData = true
      var data: seq[byte]
      try:
        data = hexToBytes(v.getStr())
      except CatchableError:
        raise newRpcError(RpcTypeError, "Data must be hexadecimal string")
      # OP_RETURN <push data> — same builder as walletcreatefundedpsbt.
      var script: seq[byte]
      script.add(0x6a'u8)            # OP_RETURN
      if data.len <= 75:
        script.add(byte(data.len))
      elif data.len <= 255:
        script.add(0x4c'u8)         # OP_PUSHDATA1
        script.add(byte(data.len))
      else:
        script.add(0x4d'u8)         # OP_PUSHDATA2 (LE length)
        script.add(byte(data.len and 0xff))
        script.add(byte((data.len shr 8) and 0xff))
      script.add(data)
      outputs.add(TxOut(value: Satoshi(0), scriptPubKey: script))
    else:
      let amount = amountFromValueSat(v)
      var parsedAddr: Address
      try:
        parsedAddr = decodeAddress(k)
      except AddressError:
        raise newRpcError(RpcInvalidAddressOrKey,
          "Invalid Bitcoin address: " & k)
      if k in seenAddrs:
        raise newRpcError(RpcInvalidParameter,
          "Invalid parameter, duplicated address: " & k)
      seenAddrs.incl(k)
      let spk = scriptPubKeyForAddress(parsedAddr)
      outputs.add(TxOut(value: Satoshi(amount), scriptPubKey: spk))

  # ---- assemble unsigned tx (version 2, no witnesses → legacy serialization) ----
  let rawTx = Transaction(
    version: 2'i32,
    inputs: inputs,
    outputs: outputs,
    witnesses: @[],
    lockTime: locktime
  )
  %toHex(serialize(rawTx, includeWitness = true))

# ============================================================================
# fundrawtransaction
# ============================================================================
#
# Reference: bitcoin-core/src/wallet/rpc/spend.cpp::fundrawtransaction (706)
#            → FundTransaction (470).
#
# Raw-tx sibling of walletcreatefundedpsbt. Decode the hex raw tx, keep its
# existing inputs/outputs, then run the SAME wallet funding/coin-selection
# engine (wallet.createTransaction → coinselection.selectCoinsAdvanced /
# selectCoinsSimple) to add inputs + one change output so the wallet funds
# every output + the fee. Serialize the funded tx back to hex.
#
# Result shape EXACTLY matches Core (spend.cpp:831-834):
#   { "hex": <funded raw tx hex>, "fee": <BTC>, "changepos": <int or -1> }
#
# We REUSE the funding core rather than reimplementing coin selection: the
# auto-fund path calls Wallet.createTransaction (the same proc the auto-fund
# branch of handleWalletCreateFundedPsbt above goes through). The only
# difference is the serializer at the end: hex instead of PSBT.

proc decodeRawTxLegacyForced(data: seq[byte]): Transaction =
  ## Parse a raw tx WITHOUT the segwit-marker heuristic (Core's DecodeHexTx
  ## try_witness=false path). Needed because an input tx produced by
  ## createrawtransaction with an empty vin serializes as
  ## `version | 0x00 (vin count) | vout… | locktime`, and the witness-aware
  ## deserializeTransaction mis-reads that leading 0x00 as a segwit marker.
  ## Thin wrapper over the shared serialize.nim decoder so the legacy-forced
  ## path is identical everywhere it is used.
  deserializeTransactionLegacyForced(data)

proc handleFundRawTransaction(rpc: RpcServer, params: JsonNode): JsonNode =
  ## fundrawtransaction "hexstring" ( options iswitness )
  ##
  ## Arguments:
  ## 1. hexstring (string, required) — raw tx hex to fund
  ## 2. options   (object, optional) — {changeAddress, changePosition,
  ##                                    feeRate (BTC/kvB), fee_rate (sat/vB),
  ##                                    subtractFeeFromOutputs, lockUnspents,
  ##                                    includeWatching, replaceable, ...}
  ## 3. iswitness (bool, optional)   — accepted (decoder is witness-aware)
  ##
  ## Returns: { hex: <funded raw tx>, fee: BTC, changepos: int (-1 if none) }
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing required parameter: hexstring")

  var w = rpc.getTargetWallet()

  # ---- 1. Decode the raw tx (keeps existing inputs/outputs). ----
  # Mirror Core's DecodeHexTx try_witness/try_no_witness heuristic
  # (spend.cpp:806-810): iswitness present → force that mode; absent → try
  # witness-aware first, then fall back to legacy (handles empty-vin tx hex
  # built by createrawtransaction, whose leading 0x00 vin-count would be
  # mis-read as a segwit marker by the witness-aware deserializer).
  let txHex = params[0].getStr()
  var tryWitness = true
  var tryNoWitness = true
  if params.len >= 3 and params[2].kind == JBool:
    tryWitness = params[2].getBool()
    tryNoWitness = not tryWitness
  var rawTx: Transaction
  var rawBytes: seq[byte]
  try:
    rawBytes = hexToBytes(txHex)
  except CatchableError:
    raise newRpcError(-22, "TX decode failed")
  var decoded = false
  if tryWitness:
    try:
      rawTx = deserializeTransaction(rawBytes)
      # Core's DecodeTx (core_io.cpp) only accepts a witness-aware decode when
      # the stream is FULLY consumed (`ssData.empty()`). deserializeTransaction
      # does not report consumed length, so use the robust proxy: re-serialize
      # the parsed tx witness-aware and require it to reproduce rawBytes exactly.
      # fundrawtransaction's PRIMARY input is an empty-vin tx (outputs, 0 inputs)
      # whose leading 0x00 is mis-read here as a segwit marker, leaving the real
      # output bytes UNCONSUMED. Without this check `decoded` would be true and
      # the legacy fallback would never fire, silently DROPPING the outputs.
      if serialize(rawTx, includeWitness = true) == rawBytes:
        decoded = true
      else:
        decoded = false
    except CatchableError:
      decoded = false
  if not decoded and tryNoWitness:
    try:
      rawTx = decodeRawTxLegacyForced(rawBytes)
      decoded = true
    except CatchableError:
      decoded = false
  if not decoded:
    # Core: RPC_DESERIALIZATION_ERROR (-22) "TX decode failed".
    raise newRpcError(-22, "TX decode failed")

  let existingInputs = rawTx.inputs
  let existingOutputs = rawTx.outputs

  # ---- 2. Parse options. ----
  var feeRate = 0.0           # sat/vB; 0 means "use estimator"
  var changeAddrOverride = ""
  var changePosOpt = -1       # requested change position; -1 = append at end
  var changePosSpecified = false
  var sffo: seq[int]          # subtractFeeFromOutputs indices
  var replaceable = true      # Core DEFAULT_WALLET_RBF = true

  if params.len >= 2 and params[1].kind == JObject:
    let opts = params[1]
    # fee_rate (sat/vB) takes precedence over feeRate (BTC/kvB), matching Core.
    if opts.hasKey("fee_rate") and opts["fee_rate"].kind != JNull:
      feeRate = opts["fee_rate"].getFloat()
    elif opts.hasKey("feeRate") and opts["feeRate"].kind != JNull:
      feeRate = opts["feeRate"].getFloat() * 100_000_000.0 / 1000.0
    if opts.hasKey("changeAddress") and opts["changeAddress"].kind != JNull:
      changeAddrOverride = opts["changeAddress"].getStr()
    elif opts.hasKey("change_address") and opts["change_address"].kind != JNull:
      changeAddrOverride = opts["change_address"].getStr()
    if opts.hasKey("changePosition") and opts["changePosition"].kind != JNull:
      changePosOpt = opts["changePosition"].getInt()
      changePosSpecified = true
    elif opts.hasKey("change_position") and opts["change_position"].kind != JNull:
      changePosOpt = opts["change_position"].getInt()
      changePosSpecified = true
    if opts.hasKey("replaceable") and opts["replaceable"].kind == JBool:
      replaceable = opts["replaceable"].getBool()
    let sffoKey =
      if opts.hasKey("subtractFeeFromOutputs"): "subtractFeeFromOutputs"
      elif opts.hasKey("subtract_fee_from_outputs"): "subtract_fee_from_outputs"
      else: ""
    if sffoKey.len > 0 and opts[sffoKey].kind == JArray:
      for idx in opts[sffoKey]:
        sffo.add(idx.getInt())

  # changePosition out-of-bounds guard (Core spend.cpp:534 — pos must be in
  # [0, recipients.size()], where recipients = the existing outputs).
  if changePosSpecified and
     (changePosOpt < 0 or changePosOpt > existingOutputs.len):
    raise newRpcError(RpcInvalidParameter, "changePosition out of bounds")

  if feeRate <= 0.0:
    if rpc.feeEstimator != nil:
      feeRate = rpc.feeEstimator.estimateFee(6)
    else:
      feeRate = FallbackFeeRate

  # ---- 3. Fund via the existing coin-selection engine. ----
  # createTransaction takes the requested outputs, selects coins to cover
  # outputs + fee, and appends a change output (when change > dust). This is
  # the same path the auto-fund branch of walletcreatefundedpsbt uses.
  var fundedTx: Transaction
  var changePos = -1
  let hadChangeAppendIdx = existingOutputs.len  # index change lands at, if any

  if existingInputs.len == 0:
    # No pre-selected inputs → pure auto-fund. Reuse createTransaction.
    try:
      fundedTx = w.createTransaction(existingOutputs, feeRate)
    except WalletError as e:
      raise newRpcError(RpcWalletError, e.msg)
    except CoinSelectionError as e:
      # Core surfaces insufficient-funds as RPC_WALLET_ERROR.
      raise newRpcError(RpcWalletError, e.msg)
    if fundedTx.outputs.len > existingOutputs.len:
      changePos = hadChangeAppendIdx
  else:
    # Pre-existing inputs present. Fund the shortfall with createTransaction,
    # then prepend the caller's existing inputs (Core keeps existing inputs and
    # adds more via coin selection). createTransaction's selector covers the
    # full output+fee amount; the caller's inputs add headroom. We union the
    # input sets, de-duplicating, and recompute change from actual totalIn.
    try:
      fundedTx = w.createTransaction(existingOutputs, feeRate)
    except WalletError as e:
      raise newRpcError(RpcWalletError, e.msg)
    except CoinSelectionError as e:
      raise newRpcError(RpcWalletError, e.msg)
    if fundedTx.outputs.len > existingOutputs.len:
      changePos = hadChangeAppendIdx
    # Splice caller's existing inputs in front, skipping any the selector
    # already chose (avoid double-spend within the tx).
    var seen: HashSet[OutPoint]
    for inp in fundedTx.inputs:
      seen.incl(inp.prevOut)
    var mergedInputs: seq[TxIn]
    for inp in existingInputs:
      if inp.prevOut notin seen:
        mergedInputs.add(inp)
        seen.incl(inp.prevOut)
    mergedInputs.add(fundedTx.inputs)
    fundedTx.inputs = mergedInputs
    fundedTx.witnesses = newSeq[seq[seq[byte]]](fundedTx.inputs.len)

  # ---- 4. Preserve caller locktime/version; apply RBF semantics. ----
  fundedTx.version = rawTx.version
  fundedTx.lockTime = rawTx.lockTime
  if not replaceable:
    let nonRbfDefault: uint32 =
      if rawTx.lockTime > 0: 0xfffffffe'u32 else: 0xffffffff'u32
    for i in 0 ..< fundedTx.inputs.len:
      if fundedTx.inputs[i].sequence == 0xfffffffd'u32:
        fundedTx.inputs[i].sequence = nonRbfDefault

  # ---- 5. Optional changeAddress override. ----
  if changePos >= 0 and changeAddrOverride.len > 0:
    try:
      let parsed = decodeAddress(changeAddrOverride)
      fundedTx.outputs[changePos].scriptPubKey = scriptPubKeyForAddress(parsed)
    except AddressError as e:
      raise newRpcError(RpcInvalidAddressOrKey,
        "Change address must be a valid bitcoin address: " & e.msg)

  # ---- 6. Optional changePosition relocation. ----
  if changePos >= 0 and changePosSpecified and changePosOpt != changePos:
    let changeOut = fundedTx.outputs[changePos]
    fundedTx.outputs.delete(changePos)
    fundedTx.outputs.insert(changeOut, changePosOpt)
    changePos = changePosOpt

  # ---- 7. Compute totalIn from the selected/known UTXOs, then fee. ----
  var totalIn = Satoshi(0)
  for inp in fundedTx.inputs:
    if inp.prevOut in w.utxos:
      totalIn = totalIn + w.utxos[inp.prevOut].output.value
    elif rpc.chainState != nil:
      let u = rpc.chainState.getUtxo(inp.prevOut)
      if u.isSome:
        totalIn = totalIn + u.get().output.value
  var sumOuts = Satoshi(0)
  for o in fundedTx.outputs:
    sumOuts = sumOuts + o.value
  let fee = int64(totalIn) - int64(sumOuts)

  # ---- 7b. subtractFeeFromOutputs: shift the fee burden onto the named
  # outputs (Core's InterpretSubtractFeeFromOutputInstructions semantics).
  # The wallet selector funded the tx with the sender bearing the fee (it
  # lives in the change output). To honour SFFO we move `fee` out of the
  # named recipient outputs and into the change output, split evenly, so the
  # recipients receive less and the sender's selected inputs are unchanged.
  # Invariant sum(inputs) == sum(outputs) + fee and the `fee` value are both
  # preserved (we only reshuffle value between outputs). ----
  if sffo.len > 0 and fee > 0:
    # Validate indices against the ORIGINAL recipient outputs (pre-change).
    for idx in sffo:
      if idx < 0 or idx >= existingOutputs.len:
        raise newRpcError(RpcInvalidParameter,
          "subtractFeeFromOutputs: vout index out of bounds")
    # Map an original recipient index to its current position (change
    # insertion/relocation may have shifted indices ≥ changePos).
    proc currentIndex(origIdx: int): int =
      result = origIdx
      if changePos >= 0 and changePos <= origIdx:
        inc result
    let share = fee div int64(sffo.len)
    var remainder = fee - share * int64(sffo.len)
    var moved = Satoshi(0)
    for idx in sffo:
      let cur = currentIndex(idx)
      var take = share
      if remainder > 0:
        take += 1
        dec remainder
      let cap = int64(fundedTx.outputs[cur].value)
      if take > cap: take = cap          # never drive an output negative
      fundedTx.outputs[cur].value = Satoshi(cap - take)
      moved = moved + Satoshi(take)
    # Credit the change output with what we pulled out of the recipients so the
    # input/output balance (and therefore `fee`) stays exactly the same.
    if changePos >= 0:
      fundedTx.outputs[changePos].value =
        fundedTx.outputs[changePos].value + moved

  # ---- 8. Serialize the funded tx back to hex. ----
  # Strip empty witnesses so the serialization is non-segwit unless the caller
  # supplied witness data (the added inputs are unsigned).
  var anyWitness = false
  for wit in fundedTx.witnesses:
    if wit.len > 0:
      anyWitness = true
      break
  let hexOut = toHex(serialize(fundedTx, includeWitness = anyWitness))

  %*{
    "hex": hexOut,
    "fee": float64(fee) / 100_000_000.0,
    "changepos": changePos
  }

# ---------------------------------------------------------------------------
# bumpfee / psbtbumpfee (BIP-125 fee bumping)
# ---------------------------------------------------------------------------
#
# W118 G22 BUG-1 closure (FIX-61). nimrod is the MODEL impl for the fleet's
# universal "bumpfee MISSING" finding: the mempool already has correct BIP-125
# replacement (sequence 0xfffffffd, four-gate signal check, see
# mempool/mempool.nim:1750-1922) and createTransaction emits the opt-in
# sequence on every outgoing tx (wallet/wallet.nim:965). The only thing the
# audit found absent was the user-facing wallet RPC. This is the textbook
# "dead-helper-at-RPC-boundary" shape (machinery correct, dispatch entry
# missing) — fixing it requires almost no new business logic, just the call
# into wallet/feebumper.nim plus the JSON shape matching Core
# (wallet/rpc/spend.cpp:bumpfee_helper).

proc parseBumpFeeRequest(rpc: RpcServer, params: JsonNode): BumpFeeRequest =
  ## Shared argument parsing for bumpfee + psbtbumpfee.
  ##
  ## Core's option shape (wallet/rpc/spend.cpp:1048-1086):
  ##   options.confTarget / options.conf_target — int, default 6
  ##   options.fee_rate                          — sat/vB
  ##   options.replaceable                       — bool, default true
  ##   options.estimate_mode                     — accepted, ignored (we
  ##                                                 always use the live
  ##                                                 estimator)
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing txid parameter")
  let txidHex = params[0].getStr()
  if txidHex.len != 64:
    raise newRpcError(RpcInvalidAddressOrKey, "invalid txid length")

  result = BumpFeeRequest(
    txid: parseTxId(txidHex),
    feeRate: 0.0,         # 0 = use estimator
    confTarget: 6,
    replaceable: true
  )

  if params.len >= 2 and params[1].kind == JObject:
    let opts = params[1]
    if opts.hasKey("conf_target"):
      result.confTarget = opts["conf_target"].getInt()
    elif opts.hasKey("confTarget"):
      result.confTarget = opts["confTarget"].getInt()
    if opts.hasKey("fee_rate"):
      let v = opts["fee_rate"]
      result.feeRate =
        if v.kind == JFloat: v.getFloat() else: float64(v.getInt())
    if opts.hasKey("replaceable") and opts["replaceable"].kind == JBool:
      result.replaceable = opts["replaceable"].getBool()
    # estimate_mode is accepted-but-ignored (we only have one estimator path).

proc bumpFeeKindToRpcCode(kind: BumpFeeErrorKind): int =
  case kind
  of bfeInvalidAddressOrKey: RpcInvalidAddressOrKey
  of bfeInvalidParameter:    RpcInvalidParams
  of bfeWalletError:         RpcWalletError
  of bfeMiscError:           RpcMiscError

proc doBumpFee(rpc: RpcServer, req: BumpFeeRequest,
               wantPsbt: bool): BumpFeeOutcome =
  ## Common backbone for bumpfee + psbtbumpfee: run the wallet/feebumper.nim
  ## algorithm and translate BumpFeeError → RpcError. `wantPsbt=true` flips
  ## `require_mine` off (Core's psbtbumpfee permits foreign inputs that the
  ## caller will subsequently sign via PSBT).
  var w = rpc.getTargetWallet()

  # Unlock guard (Core's EnsureWalletIsUnlocked in bumpfee_helper:1094).
  if w.isEncrypted and w.isLocked:
    raise newRpcError(RpcMiscError,
      "wallet is locked; use walletpassphrase to unlock")

  # Pull min-relay / incremental rates from the live mempool (BIP-125 Rule 4).
  let minRelayFeeSatVb = rpc.mempool.minFeeRate
  let incrementalRelayFeeSatVb =
    rpc.mempool.incrementalRelayFeeRate / 1000.0  # sat/kvB → sat/vB

  # Determine estimator feerate (sat/vB) at confTarget. Mirrors the
  # estimator/fallback fork in handleSendToAddress (server.nim:5571).
  var estimatorFeeRate: float64
  if rpc.feeEstimator != nil:
    estimatorFeeRate = rpc.feeEstimator.estimateFee(req.confTarget)
  else:
    estimatorFeeRate = FallbackFeeRate

  try:
    return createRateBumpTransaction(
      w, rpc.mempool, rpc.chainState, req,
      requireMine = not wantPsbt,
      estimatorFeeRate = estimatorFeeRate,
      minRelayFeeSatVb = minRelayFeeSatVb,
      incrementalRelayFeeSatVb = incrementalRelayFeeSatVb
    )
  except BumpFeeError as e:
    let (kind, text) = parseBfeKind(e.msg)
    raise newRpcError(bumpFeeKindToRpcCode(kind), text)

proc handleBumpFee(rpc: RpcServer, params: JsonNode): JsonNode =
  ## bumpfee txid ( options )
  ##
  ## Replaces an unconfirmed BIP-125-replaceable wallet transaction with a
  ## higher-fee one. Returns { txid, origfee, fee, errors } per Core
  ## wallet/rpc/spend.cpp:1124-1156.
  let req = parseBumpFeeRequest(rpc, params)
  let outcome = doBumpFee(rpc, req, wantPsbt = false)

  # Sign the replacement.
  var w = rpc.getTargetWallet()
  var newTx = outcome.newTx
  try:
    if not w.signTransaction(newTx, outcome.inputUtxos):
      raise newRpcError(RpcWalletError, "Can't sign transaction.")
  except WalletError as e:
    raise newRpcError(RpcWalletError, "signing error: " & e.msg)

  # Submit (replaces the original via the existing mempool BIP-125 path).
  let acceptResult = rpc.mempool.acceptTransaction(newTx, rpc.crypto)
  if not acceptResult.isOk:
    raise newRpcError(RpcTransactionRejected,
      "Mempool rejected replacement: " & acceptResult.error)

  # Update wallet UTXO bookkeeping. The original tx's inputs are already
  # absent from wallet.utxos (sendtoaddress consumed them), but the original
  # tx's outputs (if any were ours) are about to be ejected from the mempool
  # by the replacement. They were never in wallet.utxos either (mempool
  # outputs are not yet UTXOs from the chain's perspective). So the only
  # bookkeeping needed is to (a) re-discover any change output of the new tx
  # so a subsequent bumpfee can find it again, and (b) optionally broadcast.
  let newTxid = newTx.txid()
  for voutIdx, output in newTx.outputs:
    let keyOpt = w.findKeyForScript(output.scriptPubKey)
    if keyOpt.isSome:
      let key = keyOpt.get()
      let op = OutPoint(txid: newTxid, vout: uint32(voutIdx))
      let isInternal = key.path.contains("/1/")
      # Height 0 = unconfirmed mempool output (matches sendtoaddress path).
      w.addUtxo(op, output, 0, key.path, isInternal, false)

  # Broadcast to peers (best-effort; matches handleSendToAddress).
  if rpc.peerManager != nil:
    asyncSpawn rpc.peerManager.broadcastTx(newTx)

  let txidHex = reverseHex(toHex(array[32, byte](newTxid)))
  %*{
    "txid": txidHex,
    "origfee": float64(int64(outcome.oldFee)) / 100_000_000.0,
    "fee": float64(int64(outcome.newFee)) / 100_000_000.0,
    "errors": newJArray()
  }

proc handlePsbtBumpFee(rpc: RpcServer, params: JsonNode): JsonNode =
  ## psbtbumpfee txid ( options )
  ##
  ## Same as bumpfee but returns a PSBT for an external signer instead of
  ## signing/broadcasting. Core wallet/rpc/spend.cpp:1138-1147.
  let req = parseBumpFeeRequest(rpc, params)
  let outcome = doBumpFee(rpc, req, wantPsbt = true)

  # Build PSBT around the unsigned replacement.
  var psbtObj = createPsbt(outcome.newTx)
  for i, inp in outcome.newTx.inputs:
    # Populate witnessUtxo from our pre-collected wallet/chain prev outputs.
    if i < outcome.inputUtxos.len:
      try:
        psbtObj.updateInput(i, outcome.inputUtxos[i].output, isWitness = true)
      except CatchableError:
        discard  # best-effort

  %*{
    "psbt": psbtObj.toBase64(),
    "origfee": float64(int64(outcome.oldFee)) / 100_000_000.0,
    "fee": float64(int64(outcome.newFee)) / 100_000_000.0,
    "errors": newJArray()
  }

# ============================================================================
# PayJoin sender RPCs (BIP-78) — FIX-66 W119 G26+G27 closure
# ============================================================================
#
# `getpayjoinrequest` — receiver-facing helper that mints a fresh `pj=`
# endpoint URL for the receiver to hand to a sender out-of-band. Couples
# the FIX-65 receive endpoint with the canonical address+amount BIP-21
# URI scheme. Returns:
#   { "address":..., "uri":..., "endpoint":... }
#
# `sendpayjoinrequest` — sender-facing helper that drives the full BIP-78
# outbound flow: BIP-21 parse → unsigned Original PSBT build → sign →
# POST → G10-G15 anti-snoop on the Proposal → G22 fallback on any
# failure → broadcast. Returns:
#   { "txid":..., "used_payjoin": bool, "outcome":..., "psbt":..., "error":... }
#
# Both handlers refuse if the wallet is locked. Both populate the
# RestServer's PayJoinSessionTable via REST/POST when called against a
# loopback receiver (the test wiring).

proc handleGetPayJoinRequest*(rpc: RpcServer, params: JsonNode): JsonNode =
  ## getpayjoinrequest ( amount address_type )
  ##
  ## Mint a fresh PayJoin receive URI.  Returns a BIP-21 URI like
  ##   bitcoin:bc1q...?amount=0.001&pj=https://host/payjoin
  ##
  ## Arguments:
  ##   1. amount      (numeric, optional) - BTC amount the receiver
  ##                  expects (omitted ⇒ open-amount invoice).
  ##   2. address_type (string, optional) - "bech32" (default), "legacy",
  ##                                        "p2sh-segwit", "bech32m".
  ##   3. endpoint    (string, optional) - Override the auto-built endpoint;
  ##                  useful when the receiver is behind a reverse proxy
  ##                  / .onion service. If absent, build
  ##                  `http://127.0.0.1:<rpcPort + 1>/payjoin` (placeholder;
  ##                  in production the operator supplies the real URL).
  ##
  ## Returns:
  ##   { "address": "...", "uri": "bitcoin:...?pj=...", "endpoint": "...",
  ##     "amount": <float, optional> }
  ##
  ## Reference: BIP-21 §"Payment URI" + BIP-78 §"BIP-21 extension".
  var w = rpc.getTargetWallet()
  if w.isEncrypted and w.isLocked:
    raise newRpcError(RpcMiscError,
      "wallet is locked; use walletpassphrase to unlock")

  # Parse args.
  var amountBtc = 0.0
  var hasAmount = false
  if params.len >= 1:
    if params[0].kind == JFloat:
      amountBtc = params[0].getFloat()
      hasAmount = amountBtc > 0
    elif params[0].kind == JInt:
      amountBtc = float64(params[0].getInt())
      hasAmount = amountBtc > 0
  var addressType = "bech32"
  if params.len >= 2 and params[1].kind == JString:
    addressType = params[1].getStr()
  var endpointOverride = ""
  if params.len >= 3 and params[2].kind == JString:
    endpointOverride = params[2].getStr()

  # Mint a fresh receive address.
  let addrStr =
    try: w.getNewAddressByTypeName(addressType)
    except WalletError as e:
      raise newRpcError(RpcMiscError, e.msg)

  # Compose the receive endpoint URL. We default to a localhost http://
  # URL because the JSON-RPC server doesn't know whether the REST
  # listener has TLS — that's an operator concern. The audit only
  # requires that a URL is returned; the operator is expected to
  # publish https:// or .onion in production.
  let endpoint =
    if endpointOverride.len > 0:
      endpointOverride
    else:
      "http://127.0.0.1:" & $(rpc.port + 1) & "/payjoin"

  # Build the BIP-21 URI.
  var uriStr = "bitcoin:" & addrStr
  var qParts: seq[string] = @[]
  if hasAmount:
    qParts.add("amount=" & formatFloat(amountBtc, ffDecimal, 8))
  # Percent-encode the pj= URL just for the `:` / `/` (RFC 3986 §2.2
  # reserved). We do the minimal subset because most wallets accept the
  # raw URL unencoded.
  qParts.add("pj=" & endpoint)
  if qParts.len > 0:
    uriStr.add("?" & qParts.join("&"))

  result = %*{
    "address": addrStr,
    "uri": uriStr,
    "endpoint": endpoint
  }
  if hasAmount:
    result["amount"] = %amountBtc

proc handleNewPayJoinRequest*(rpc: RpcServer, params: JsonNode):
    JsonNode {.inline.} =
  ## Audit alias (G26).
  handleGetPayJoinRequest(rpc, params)

proc handleSendPayJoinRequest*(rpc: RpcServer, params: JsonNode): JsonNode =
  ## sendpayjoinrequest "bip21_uri" amount ( minfeerate maxadditionalfeecontribution allow_no_tls )
  ##
  ## Drive a full BIP-78 outbound PayJoin against the receiver behind
  ## `pj=` in the supplied BIP-21 URI.
  ##
  ## Arguments:
  ##   1. bip21_uri   (string, required) - The BIP-21 URI returned by
  ##                  the receiver's `getpayjoinrequest`.
  ##   2. amount      (numeric, required) - BTC amount to send. MUST
  ##                  equal the URI's `amount=` when both are set.
  ##   3. minfeerate  (numeric, optional, default=1) - sat/vB floor.
  ##   4. maxadditionalfeecontribution (numeric, optional, default=600 sat).
  ##   5. allow_no_tls (bool, optional, default=false) - test-only knob
  ##                  to bypass the G24 HTTPS check for loopback URLs.
  ##
  ## Returns:
  ##   { "txid": "...", "used_payjoin": bool, "outcome": "...",
  ##     "psbt": "...", "error_kind": "...", "error_msg": "..." }
  ##
  ## Reference: BIP-78 §"Sender".
  var w = rpc.getTargetWallet()
  if w.isEncrypted and w.isLocked:
    raise newRpcError(RpcMiscError,
      "wallet is locked; use walletpassphrase to unlock")
  if params.len < 2:
    raise newRpcError(RpcInvalidParams,
      "missing bip21_uri and/or amount parameter")

  let uriStr = params[0].getStr()
  var amountBtc: float64
  if params[1].kind == JFloat:
    amountBtc = params[1].getFloat()
  elif params[1].kind == JInt:
    amountBtc = float64(params[1].getInt())
  else:
    raise newRpcError(RpcInvalidParams, "amount must be a number")
  if amountBtc <= 0:
    raise newRpcError(RpcInvalidParams, "amount must be positive")
  let satoshis = Satoshi(int64(amountBtc * 100_000_000.0))

  let minFeeRate =
    if params.len >= 3 and params[2].kind in {JFloat, JInt}:
      if params[2].kind == JFloat: params[2].getFloat()
      else: float64(params[2].getInt())
    else: 1.0
  let maxAddFee =
    if params.len >= 4 and params[3].kind in {JFloat, JInt}:
      if params[3].kind == JFloat:
        Satoshi(int64(params[3].getFloat() * 100_000_000.0))
      else: Satoshi(params[3].getInt())
    else: Satoshi(600)
  let allowNoTls =
    if params.len >= 5 and params[4].kind == JBool:
      params[4].getBool()
    else: false

  # 1. Parse the BIP-21 URI and extract the pj= endpoint.
  let parsedUri = bip21Mod.parseBip21Uri(uriStr)
  if parsedUri.isNone:
    raise newRpcError(RpcInvalidParams,
      "invalid BIP-21 URI: " & uriStr)
  let parsed = parsedUri.get()
  if parsed.pj.isNone or parsed.pj.get().len == 0:
    raise newRpcError(RpcInvalidParams,
      "BIP-21 URI has no pj= endpoint (not PayJoin-capable)")
  let endpoint = parsed.pj.get()

  # 2. Decode the address and build the unsigned Original tx.
  var destAddr: Address
  try:
    destAddr = decodeAddress(parsed.address)
  except AddressError as e:
    raise newRpcError(RpcInvalidAddressOrKey,
      "invalid address in URI: " & e.msg)
  let spk = scriptPubKeyForAddress(destAddr)
  var feeRate: float64
  if rpc.feeEstimator != nil:
    feeRate = rpc.feeEstimator.estimateFee(6)
    if feeRate < minFeeRate:
      feeRate = minFeeRate
  else:
    feeRate = max(minFeeRate, 1.0)

  let outputs = @[TxOut(value: satoshis, scriptPubKey: spk)]
  var tx: Transaction
  try:
    tx = w.createTransaction(outputs, feeRate)
  except WalletError as e:
    raise newRpcError(RpcTransactionError, e.msg)
  except CoinSelectionError as e:
    raise newRpcError(RpcTransactionError, e.msg)
  # Force RBF — PayJoin proposals want to inherit RBF semantics.
  for i in 0 ..< tx.inputs.len:
    tx.inputs[i].sequence = 0xfffffffd'u32

  # 3. Build a fully-signed Original PSBT.
  var utxos: seq[WalletUtxo]
  for inp in tx.inputs:
    if inp.prevOut in w.utxos:
      utxos.add(w.utxos[inp.prevOut])
    else:
      raise newRpcError(RpcTransactionError,
        "input UTXO not found in wallet")
  try:
    if not w.signTransaction(tx, utxos):
      raise newRpcError(RpcTransactionError, "failed to sign transaction")
  except WalletError as e:
    raise newRpcError(RpcTransactionError, "signing error: " & e.msg)

  var originalPsbt = createPsbt(tx)
  for i, u in utxos:
    try:
      originalPsbt.updateInput(i, u.output, isWitness = true)
    except CatchableError:
      discard
    if i < tx.witnesses.len and tx.witnesses[i].len > 0:
      originalPsbt.inputs[i].finalScriptWitness = tx.witnesses[i]
    if i < originalPsbt.inputs.len and tx.inputs[i].scriptSig.len > 0:
      originalPsbt.inputs[i].finalScriptSig = tx.inputs[i].scriptSig

  # 4. Compose query opts. Fee output is the change output (Core/payjoin
  # reference both default to the last sender-controlled output as the
  # `additionalfeeoutputindex`).
  var feeOutputIndex = -1
  for i, o in tx.outputs:
    if w.findKeyForScript(o.scriptPubKey).isSome:
      # An output we own — assume it's our change output, eligible for
      # the receiver to shrink.
      feeOutputIndex = i
  var opts = PayJoinReceiveOptions(
    version: PAYJOIN_VERSION,
    additionalFeeOutputIndex:
      if feeOutputIndex >= 0: some(feeOutputIndex) else: none(int),
    maxAdditionalFeeContribution: maxAddFee,
    minFeeRate: minFeeRate,
    disableOutputSubstitution:
      if parsed.pjos.isSome: parsed.pjos.get() else: false)
  var extraQuery = "v=1"
  if feeOutputIndex >= 0:
    extraQuery.add("&additionalfeeoutputindex=" & $feeOutputIndex)
  extraQuery.add("&maxadditionalfeecontribution=" &
    $int64(maxAddFee))
  extraQuery.add("&minfeerate=" & formatFloat(minFeeRate, ffDecimal, 2))
  if opts.disableOutputSubstitution:
    extraQuery.add("&disableoutputsubstitution=1")

  var tlsCfg = defaultPayJoinTlsConfig()
  if allowNoTls:
    tlsCfg.policy = ptsNoVerify

  # 5. Drive the sender pipeline.
  let senderResult =
    try:
      payjoinSenderRun(w, originalPsbt, endpoint, opts,
                       extraQuery = extraQuery,
                       tlsConfig = tlsCfg)
    except PayJoinSendError as e:
      raise newRpcError(RpcMiscError,
        "PayJoin sender pipeline failure: " & e.msg)

  # 6. Broadcast (either the proposal or the Original fallback).
  let finalTx = senderResult.signedTx
  let txid = finalTx.txid()
  let txidHex = reverseHex(toHex(array[32, byte](txid)))

  # Acceptance into the mempool. Failure here is a real error — the
  # sender already signed the tx; mempool rejection means we can't
  # broadcast.
  let acc = rpc.mempool.acceptTransaction(finalTx, rpc.crypto)
  if not acc.isOk:
    raise newRpcError(RpcTransactionRejected,
      "Mempool rejected " &
      (if senderResult.usedProposal: "PayJoin proposal" else: "Original fallback") &
      ": " & acc.error)

  # Wallet bookkeeping for any new wallet-owned output in the final tx.
  for voutIdx, output in finalTx.outputs:
    let keyOpt = w.findKeyForScript(output.scriptPubKey)
    if keyOpt.isSome:
      let key = keyOpt.get()
      let op = OutPoint(txid: txid, vout: uint32(voutIdx))
      let isInternal = key.path.contains("/1/")
      w.addUtxo(op, output, 0, key.path, isInternal, false)

  if rpc.peerManager != nil:
    asyncSpawn rpc.peerManager.broadcastTx(finalTx)

  result = %*{
    "txid": txidHex,
    "used_payjoin": senderResult.usedProposal,
    "outcome": $senderResult.outcome,
    "psbt": senderResult.proposalPsbtBase64,
    "error_kind": senderResult.receiverErrorKind,
    "error_msg": senderResult.receiverErrorMsg
  }

proc handleStartPayJoin*(rpc: RpcServer, params: JsonNode):
    JsonNode {.inline.} =
  ## Audit alias (G27).
  handleSendPayJoinRequest(rpc, params)

proc handleDecodePsbt(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Decode a PSBT and return its contents
  ## Reference: Bitcoin Core rpc/rawtransaction.cpp decodepsbt
  ##
  ## Arguments:
  ## 1. psbt (string, required) - Base64-encoded PSBT
  ##
  ## Returns: JSON object with PSBT details

  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing psbt parameter")

  let psbtBase64 = params[0].getStr()

  var psbtObj: Psbt
  try:
    psbtObj = fromBase64(psbtBase64)
  except PsbtError as e:
    raise newRpcError(RpcInvalidParams, "invalid PSBT: " & e.msg)
  except CatchableError as e:
    raise newRpcError(RpcInvalidParams, "invalid PSBT: " & e.msg)

  let mainnet = rpc.params.network == Mainnet

  # Build decoded transaction
  var txJson = newJObject()
  if psbtObj.tx.isSome:
    let tx = psbtObj.tx.get()
    let txid = tx.txid()
    let weight = validation.calculateTransactionWeight(tx)
    let vsize = (weight + 3) div 4

    txJson["txid"] = %reverseHex(toHex(array[32, byte](txid)))
    txJson["hash"] = %reverseHex(toHex(array[32, byte](tx.wtxid())))
    txJson["version"] = %tx.version
    txJson["size"] = %serialize(tx).len
    txJson["vsize"] = %vsize
    txJson["weight"] = %weight
    txJson["locktime"] = %tx.lockTime

    # Build vin array
    var vinArray = newJArray()
    for i, inp in tx.inputs:
      var vinObj = %*{
        "txid": reverseHex(toHex(array[32, byte](inp.prevOut.txid))),
        "vout": inp.prevOut.vout,
        "scriptSig": %*{
          "asm": "",
          "hex": ""
        },
        "sequence": inp.sequence
      }
      vinArray.add(vinObj)
    txJson["vin"] = vinArray

    # Build vout array
    var voutArray = newJArray()
    for i, outp in tx.outputs:
      voutArray.add(buildVoutJson(outp, i, mainnet))
    txJson["vout"] = voutArray

  # Build inputs array with PSBT metadata
  var inputsArray = newJArray()
  var totalInputValue = Satoshi(0)
  var hasAllUtxos = true

  for i, inp in psbtObj.inputs:
    var inputObj = newJObject()

    # UTXO info
    # Reference: bitcoin-core/src/rpc/rawtransaction.cpp lines 1122-1156.
    # Core uses a single `txout` variable overwritten by both utxo branches;
    # the final `txout.nValue` is added to `total_in` exactly once.
    # When both witness_utxo AND non_witness_utxo are present the
    # non_witness_utxo branch runs second and its vout value wins.
    # We track haveAUtxo and the winning value separately to avoid double-add.
    var haveAUtxo = false
    var inputUtxoValue = Satoshi(0)

    if inp.witnessUtxo.isSome:
      let utxo = inp.witnessUtxo.get()
      inputObj["witness_utxo"] = %*{
        "amount": btcAmountNode(int64(utxo.value)),
        "scriptPubKey": buildScriptPubKeyJson(utxo.scriptPubKey, mainnet)
      }
      inputUtxoValue = utxo.value
      haveAUtxo = true

    if inp.nonWitnessUtxo.isSome:
      let prevTx = inp.nonWitnessUtxo.get()
      inputObj["non_witness_utxo"] = buildNonWitnessUtxoJson(prevTx, mainnet)
      # non_witness_utxo overwrites the value (same as Core's txout overwrite)
      if psbtObj.tx.isSome:
        let outpoint = psbtObj.tx.get().inputs[i].prevOut
        if int(outpoint.vout) < prevTx.outputs.len:
          inputUtxoValue = prevTx.outputs[outpoint.vout].value
          haveAUtxo = true
        else:
          hasAllUtxos = false
      else:
        hasAllUtxos = false

    if haveAUtxo:
      totalInputValue = totalInputValue + inputUtxoValue
    else:
      hasAllUtxos = false

    # Partial signatures
    if inp.partialSigs.len > 0:
      var sigsObj = newJObject()
      for pubkey, sig in inp.partialSigs:
        sigsObj[toHex(pubkey)] = %toHex(sig)
      inputObj["partial_signatures"] = sigsObj

    # Sighash type — emit the string label ("ALL", "NONE", "SINGLE", ...)
    # Reference: bitcoin-core/src/core_io.cpp SighashToStr (called from decodepsbt
    # rpc/rawtransaction.cpp line ~1169). Empty string for unknown types.
    if inp.sighashType.isSome:
      inputObj["sighash"] = %sighashToStr(inp.sighashType.get())

    # Scripts — emit {asm, hex, type} via buildScriptTypeJson.
    # Reference: bitcoin-core/src/rpc/rawtransaction.cpp lines 1173-1182,
    # which calls ScriptToUniv with default args (include_address=false),
    # so NO desc and NO address are emitted — only asm + hex + type.
    if inp.redeemScript.len > 0:
      inputObj["redeem_script"] = buildScriptTypeJson(inp.redeemScript)

    if inp.witnessScript.len > 0:
      inputObj["witness_script"] = buildScriptTypeJson(inp.witnessScript)

    # BIP32 derivation paths
    # Reference: bitcoin-core/src/util/bip32.cpp WriteHDKeypath(path) — default
    # apostrophe=false, so hardened components use 'h' not "'".
    if inp.hdKeypaths.len > 0:
      var derivsArray = newJArray()
      for pubkey, origin in inp.hdKeypaths:
        var pathStr = "m"
        for idx in origin.path:
          if (idx and 0x80000000'u32) != 0:
            pathStr.add("/" & $(idx and 0x7fffffff'u32) & "h")
          else:
            pathStr.add("/" & $idx)
        derivsArray.add(%*{
          "pubkey": toHex(pubkey),
          "master_fingerprint": toHex(origin.fingerprint),
          "path": pathStr
        })
      inputObj["bip32_derivs"] = derivsArray

    # Final scripts — final_scriptSig.asm uses sighash-decode mode (true).
    # Reference: bitcoin-core/src/rpc/rawtransaction.cpp line 1201:
    #   scriptsig.pushKV("asm", ScriptToAsmStr(input.final_script_sig, true))
    # The 'true' means DER sigs have their last byte decoded as e.g. "[ALL]".
    if inp.finalScriptSig.len > 0:
      inputObj["final_scriptSig"] = %*{
        "asm": disassembleScriptSigAsmStr(inp.finalScriptSig),
        "hex": toHex(inp.finalScriptSig)
      }

    if inp.finalScriptWitness.len > 0:
      var witnessArray = newJArray()
      for item in inp.finalScriptWitness:
        witnessArray.add(%toHex(item))
      inputObj["final_scriptwitness"] = witnessArray

    # Taproot fields (BIP-371)
    # taproot_key_path_sig (0x13)
    if inp.tapKeySig.len > 0:
      inputObj["taproot_key_path_sig"] = %toHex(inp.tapKeySig)

    # taproot_script_path_sigs (0x14) — array of {pubkey, leaf_hash, sig}
    # Core iterates m_tap_script_sigs (std::map sorted by (xonly, leaf_hash))
    if inp.tapScriptSigs.len > 0:
      var scriptSigsArray = newJArray()
      var sortedKeys: seq[(array[32, byte], array[32, byte])]
      for keyPair in inp.tapScriptSigs.keys:
        sortedKeys.add(keyPair)
      sortedKeys.sort(proc(a, b: (array[32, byte], array[32, byte])): int =
        for i in 0 ..< 32:
          if a[0][i] < b[0][i]: return -1
          if a[0][i] > b[0][i]: return 1
        for i in 0 ..< 32:
          if a[1][i] < b[1][i]: return -1
          if a[1][i] > b[1][i]: return 1
        0)
      for keyPair in sortedKeys:
        let sig = inp.tapScriptSigs[keyPair]
        scriptSigsArray.add(%*{
          "pubkey": toHex(keyPair[0]),
          "leaf_hash": toHex(keyPair[1]),
          "sig": toHex(sig)
        })
      inputObj["taproot_script_path_sigs"] = scriptSigsArray

    # taproot_scripts (0x15) — array of {script, leaf_ver, control_blocks[]}
    # Core iterates m_tap_scripts: std::map<(script, leaf_ver), set<control_block>>
    if inp.tapScripts.len > 0:
      var tapScriptsArray = newJArray()
      # Sort by (script_hex, leaf_ver) for determinism
      var sortedLeafKeys: seq[(seq[byte], int)]
      for leafKey in inp.tapScripts.keys:
        sortedLeafKeys.add(leafKey)
      sortedLeafKeys.sort(proc(a, b: (seq[byte], int)): int =
        let minLen = min(a[0].len, b[0].len)
        for i in 0 ..< minLen:
          if a[0][i] < b[0][i]: return -1
          if a[0][i] > b[0][i]: return 1
        if a[0].len < b[0].len: return -1
        if a[0].len > b[0].len: return 1
        cmp(a[1], b[1]))
      for leafKey in sortedLeafKeys:
        let controlBlocks = inp.tapScripts[leafKey]
        var cbArray = newJArray()
        var sortedCbs: seq[seq[byte]]
        for cb in controlBlocks:
          sortedCbs.add(cb)
        sortedCbs.sort(proc(a, b: seq[byte]): int =
          let minLen = min(a.len, b.len)
          for i in 0 ..< minLen:
            if a[i] < b[i]: return -1
            if a[i] > b[i]: return 1
          cmp(a.len, b.len))
        for cb in sortedCbs:
          cbArray.add(%toHex(cb))
        tapScriptsArray.add(%*{
          "script": toHex(leafKey[0]),
          "leaf_ver": leafKey[1],
          "control_blocks": cbArray
        })
      inputObj["taproot_scripts"] = tapScriptsArray

    # taproot_bip32_derivs (0x16) — array of {pubkey, master_fingerprint, path, leaf_hashes[]}
    # Core iterates m_tap_bip32_paths: std::map<XOnlyPubKey, ...> (lex sorted by pubkey)
    if inp.tapBip32Paths.len > 0:
      var tapDerivArray = newJArray()
      var sortedXonlys: seq[array[32, byte]]
      for xonly in inp.tapBip32Paths.keys:
        sortedXonlys.add(xonly)
      sortedXonlys.sort(proc(a, b: array[32, byte]): int =
        for i in 0 ..< 32:
          if a[i] < b[i]: return -1
          if a[i] > b[i]: return 1
        0)
      for xonly in sortedXonlys:
        let (leafHashes, origin) = inp.tapBip32Paths[xonly]
        var pathStr = "m"
        for idx in origin.path:
          if (idx and 0x80000000'u32) != 0:
            pathStr.add("/" & $(idx and 0x7fffffff'u32) & "h")
          else:
            pathStr.add("/" & $idx)
        var leafHashesArray = newJArray()
        var sortedLeafHashes: seq[array[32, byte]]
        for lh in leafHashes:
          sortedLeafHashes.add(lh)
        sortedLeafHashes.sort(proc(a, b: array[32, byte]): int =
          for i in 0 ..< 32:
            if a[i] < b[i]: return -1
            if a[i] > b[i]: return 1
          0)
        for lh in sortedLeafHashes:
          leafHashesArray.add(%toHex(lh))
        tapDerivArray.add(%*{
          "pubkey": toHex(xonly),
          "master_fingerprint": toHex(origin.fingerprint),
          "path": pathStr,
          "leaf_hashes": leafHashesArray
        })
      inputObj["taproot_bip32_derivs"] = tapDerivArray

    # taproot_internal_key (0x17)
    if inp.tapInternalKey != default(array[32, byte]):
      inputObj["taproot_internal_key"] = %toHex(inp.tapInternalKey)

    # taproot_merkle_root (0x18)
    if inp.tapMerkleRoot != default(array[32, byte]):
      inputObj["taproot_merkle_root"] = %toHex(inp.tapMerkleRoot)

    inputsArray.add(inputObj)

  # Build outputs array with PSBT metadata
  var outputsArray = newJArray()
  for outp in psbtObj.outputs:
    var outputObj = newJObject()

    if outp.redeemScript.len > 0:
      outputObj["redeem_script"] = %*{
        "asm": disassembleScript(outp.redeemScript),
        "hex": toHex(outp.redeemScript)
      }

    if outp.witnessScript.len > 0:
      outputObj["witness_script"] = %*{
        "asm": disassembleScript(outp.witnessScript),
        "hex": toHex(outp.witnessScript)
      }

    if outp.hdKeypaths.len > 0:
      var derivsArray = newJArray()
      for pubkey, origin in outp.hdKeypaths:
        var pathStr = "m"
        for idx in origin.path:
          if (idx and 0x80000000'u32) != 0:
            pathStr.add("/" & $(idx and 0x7fffffff'u32) & "h")
          else:
            pathStr.add("/" & $idx)
        derivsArray.add(%*{
          "pubkey": toHex(pubkey),
          "master_fingerprint": toHex(origin.fingerprint),
          "path": pathStr
        })
      outputObj["bip32_derivs"] = derivsArray

    # taproot_internal_key (PSBT_OUT_TAP_INTERNAL_KEY = 0x05)
    if outp.tapInternalKey != default(array[32, byte]):
      outputObj["taproot_internal_key"] = %toHex(outp.tapInternalKey)

    # taproot_tree (PSBT_OUT_TAP_TREE = 0x06) — array of {depth, leaf_ver, script}
    if outp.tapTree.len > 0:
      var treeArray = newJArray()
      for (depth, leafVer, script) in outp.tapTree:
        treeArray.add(%*{
          "depth": int(depth),
          "leaf_ver": int(leafVer),
          "script": toHex(script)
        })
      outputObj["taproot_tree"] = treeArray

    # taproot_bip32_derivs (PSBT_OUT_TAP_BIP32_DERIVATION = 0x07)
    # Core iterates std::map<XOnlyPubKey, ...> (lex sorted by pubkey)
    if outp.tapBip32Paths.len > 0:
      var tapDerivArray = newJArray()
      var sortedXonlys: seq[array[32, byte]]
      for xonly in outp.tapBip32Paths.keys:
        sortedXonlys.add(xonly)
      sortedXonlys.sort(proc(a, b: array[32, byte]): int =
        for i in 0 ..< 32:
          if a[i] < b[i]: return -1
          if a[i] > b[i]: return 1
        0)
      for xonly in sortedXonlys:
        let (leafHashes, origin) = outp.tapBip32Paths[xonly]
        var pathStr = "m"
        for idx in origin.path:
          if (idx and 0x80000000'u32) != 0:
            pathStr.add("/" & $(idx and 0x7fffffff'u32) & "h")
          else:
            pathStr.add("/" & $idx)
        var leafHashesArray = newJArray()
        var sortedLeafHashes: seq[array[32, byte]]
        for lh in leafHashes:
          sortedLeafHashes.add(lh)
        sortedLeafHashes.sort(proc(a, b: array[32, byte]): int =
          for i in 0 ..< 32:
            if a[i] < b[i]: return -1
            if a[i] > b[i]: return 1
          0)
        for lh in sortedLeafHashes:
          leafHashesArray.add(%toHex(lh))
        tapDerivArray.add(%*{
          "pubkey": toHex(xonly),
          "master_fingerprint": toHex(origin.fingerprint),
          "path": pathStr,
          "leaf_hashes": leafHashesArray
        })
      outputObj["taproot_bip32_derivs"] = tapDerivArray

    # musig2_participant_pubkeys (PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS = 0x08)
    # Core emits array of {aggregate_pubkey, participant_pubkeys[]}
    # Core's std::map is sorted by aggregate_pubkey (lex order)
    if outp.musig2Participants.len > 0:
      var musigArray = newJArray()
      var sortedAggKeys: seq[seq[byte]]
      for aggKey in outp.musig2Participants.keys:
        sortedAggKeys.add(aggKey)
      sortedAggKeys.sort(proc(a, b: seq[byte]): int =
        let minLen = min(a.len, b.len)
        for i in 0 ..< minLen:
          if a[i] < b[i]: return -1
          if a[i] > b[i]: return 1
        cmp(a.len, b.len))
      for aggKey in sortedAggKeys:
        let participants = outp.musig2Participants[aggKey]
        var partArray = newJArray()
        for pk in participants:
          partArray.add(%toHex(pk))
        musigArray.add(%*{
          "aggregate_pubkey": toHex(aggKey),
          "participant_pubkeys": partArray
        })
      outputObj["musig2_participant_pubkeys"] = musigArray

    outputsArray.add(outputObj)

  # Calculate fee if we have all UTXOs.  Emit Core-shaped fixed 8-decimal
  # amount (see `btcAmountNode`).
  var feeNode = newJNull()
  if hasAllUtxos and psbtObj.tx.isSome:
    var totalOutput = Satoshi(0)
    for outp in psbtObj.tx.get().outputs:
      totalOutput = totalOutput + outp.value
    if int64(totalInputValue) >= int64(totalOutput):
      let fee = totalInputValue - totalOutput
      feeNode = btcAmountNode(int64(fee))

  result = %*{
    "tx": txJson,
    "global_xpubs": newJArray(),
    "psbt_version": psbtObj.version.get(0),
    "proprietary": newJArray(),
    "unknown": newJObject(),
    "inputs": inputsArray,
    "outputs": outputsArray
  }

  if feeNode.kind != JNull:
    result["fee"] = feeNode

proc handleCombinePsbt(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Combine multiple PSBTs into one
  ## Reference: Bitcoin Core rpc/rawtransaction.cpp combinepsbt
  ##
  ## Arguments:
  ## 1. psbts (array, required) - Array of base64-encoded PSBTs
  ##
  ## Returns: Combined base64-encoded PSBT

  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing psbts parameter")

  if params[0].kind != JArray:
    raise newRpcError(RpcInvalidParams, "psbts must be an array")

  if params[0].len == 0:
    raise newRpcError(RpcInvalidParams, "psbts array is empty")

  var psbts: seq[Psbt]
  for psbtNode in params[0]:
    if psbtNode.kind != JString:
      raise newRpcError(RpcInvalidParams, "each PSBT must be a base64 string")

    try:
      psbts.add(fromBase64(psbtNode.getStr()))
    except PsbtError as e:
      raise newRpcError(RpcInvalidParams, "invalid PSBT: " & e.msg)
    except CatchableError as e:
      raise newRpcError(RpcInvalidParams, "invalid PSBT: " & e.msg)

  # Combine all PSBTs
  var combined: Psbt
  try:
    combined = combinePsbts(psbts)
  except PsbtError as e:
    raise newRpcError(RpcInvalidParams, "cannot combine: " & e.msg)

  %combined.toBase64()

proc handleConvertToPsbt(rpc: RpcServer, params: JsonNode): JsonNode =
  ## converttopsbt "hexstring" ( permitsigdata iswitness )
  ##
  ## Converts a network-serialized raw transaction into a blank PSBT. This is
  ## an OFFLINE helper — it reads no chainstate/wallet. Mirrors Core's
  ## `converttopsbt` (bitcoin-core/src/rpc/rawtransaction.cpp:1663).
  ##
  ## Arguments:
  ## 1. hexstring     (string, required) — raw transaction hex.
  ## 2. permitsigdata (bool, optional, default=false) — if false, RPC fails
  ##    when any input carries a scriptSig or witness; if true those are
  ##    silently discarded.
  ## 3. iswitness     (bool, optional) — force witness/non-witness decode.
  ##    Absent → heuristic (try witness-aware first, fall back to legacy).
  ##
  ## Returns: base64-encoded PSBT string.
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing required parameter: hexstring")

  let permitSigData =
    if params.len >= 2 and params[1].kind == JBool: params[1].getBool() else: false

  # Core DecodeHexTx heuristic (rawtransaction.cpp:1695-1701): iswitness
  # present forces that single mode; absent tries both (witness first, then
  # the legacy decoder so an empty-vin tx whose leading 0x00 would be mistaken
  # for a segwit marker still parses).
  var tryWitness = true
  var tryNoWitness = true
  if params.len >= 3 and params[2].kind == JBool:
    tryWitness = params[2].getBool()
    tryNoWitness = not tryWitness

  var rawBytes: seq[byte]
  try:
    rawBytes = hexToBytes(params[0].getStr())
  except CatchableError:
    raise newRpcError(RpcDeserializationError, "TX decode failed")

  var tx: Transaction
  var decoded = false
  if tryWitness:
    try:
      tx = deserializeTransaction(rawBytes)
      # Core's DecodeTx (core_io.cpp DecodeTx) only accepts a candidate decode
      # when the stream is FULLY consumed (`ssData.empty()`). deserializeTransaction
      # does not report consumed length, so use the robust proxy: re-serialize the
      # parsed tx witness-aware and require it to reproduce rawBytes exactly. The
      # empty-vin tx `02..00 (vin=0) <vout> ..` mis-parses here as a 0-input/0-output
      # segwit tx whose leading 0x00 is read as a marker, leaving trailing bytes
      # UNCONSUMED. Without this check `decoded` would be true and the legacy
      # fallback would never fire, silently dropping the real output.
      if serialize(tx, includeWitness = true) == rawBytes:
        decoded = true
      else:
        decoded = false
    except CatchableError:
      decoded = false
  if not decoded and tryNoWitness:
    try:
      tx = decodeRawTxLegacyForced(rawBytes)
      decoded = true
    except CatchableError:
      decoded = false
  if not decoded:
    raise newRpcError(RpcDeserializationError, "TX decode failed")

  # Normalize the witnesses array so per-input checks are well-defined.
  if tx.witnesses.len < tx.inputs.len:
    let oldLen = tx.witnesses.len
    tx.witnesses.setLen(tx.inputs.len)
    for i in oldLen ..< tx.inputs.len:
      tx.witnesses[i] = @[]

  # Reject sig data unless permitted, then clear ALL scriptSigs/witnesses
  # unconditionally (Core rawtransaction.cpp:1704-1710).
  for i in 0 ..< tx.inputs.len:
    let hasScriptSig = tx.inputs[i].scriptSig.len > 0
    let hasWitness = i < tx.witnesses.len and tx.witnesses[i].len > 0
    if (hasScriptSig or hasWitness) and not permitSigData:
      raise newRpcError(RpcDeserializationError,
        "Inputs must not have scriptSigs and scriptWitnesses")
  for i in 0 ..< tx.inputs.len:
    tx.inputs[i].scriptSig = @[]
  tx.witnesses = @[]

  # Build a blank PSBT (empty per-input/output maps; createPsbt allocates one
  # PsbtInput per vin and one PsbtOutput per vout). createPsbt re-checks the
  # scriptSigs are empty — they are, since we just cleared them.
  let psbtObj = createPsbt(tx)
  %psbtObj.toBase64()

proc shufflePsbtIndices(n: int): seq[int] =
  ## Fisher-Yates shuffle of [0, n) using cryptographic randomness (sysrand),
  ## mirroring Core's std::shuffle(..., FastRandomContext()) in joinpsbts. The
  ## shuffle is for on-wire input/output privacy only — joinpsbts callers must
  ## treat the result as an unordered set of inputs + set of outputs.
  result = newSeq[int](n)
  for i in 0 ..< n:
    result[i] = i
  for i in countdown(n - 1, 1):
    var raw: array[8, byte]
    discard urandom(raw)
    var v = 0'u64
    for b in raw:
      v = (v shl 8) or uint64(b)
    let j = int(v mod uint64(i + 1))
    let tmp = result[i]
    result[i] = result[j]
    result[j] = tmp

proc handleJoinPsbts(rpc: RpcServer, params: JsonNode): JsonNode =
  ## joinpsbts ["psbt", ...]
  ##
  ## Joins multiple DISTINCT PSBTs (no shared input) into one PSBT carrying the
  ## union of all inputs and outputs. OFFLINE — no chainstate/wallet access.
  ## Mirrors Core's `joinpsbts` (bitcoin-core/src/rpc/rawtransaction.cpp:1778).
  ##
  ## Arguments:
  ## 1. txs (array of base64 PSBT strings, required) — at least two.
  ##
  ## Returns: base64-encoded merged PSBT. The merged tx takes the MAX version
  ## and MIN nLockTime across inputs. Inputs/outputs are shuffled for privacy,
  ## so callers must compare as sets, not by byte order.
  if params.len < 1 or params[0].kind != JArray:
    raise newRpcError(RpcInvalidParameter,
      "At least two PSBTs are required to join PSBTs.")

  let txs = params[0]
  # Core: txs.size() <= 1 → RPC_INVALID_PARAMETER (-8).
  if txs.len <= 1:
    raise newRpcError(RpcInvalidParameter,
      "At least two PSBTs are required to join PSBTs.")

  var psbtxs: seq[Psbt]
  var bestVersion = 1'u32
  var bestLocktime = 0xffffffff'u32
  for node in txs:
    if node.kind != JString:
      raise newRpcError(RpcDeserializationError, "TX decode failed")
    var p: Psbt
    try:
      p = fromBase64(node.getStr())
    except CatchableError as e:
      # Core: RPC_DESERIALIZATION_ERROR (-22) "TX decode failed <err>".
      raise newRpcError(RpcDeserializationError, "TX decode failed " & e.msg)
    if p.tx.isNone:
      raise newRpcError(RpcDeserializationError, "TX decode failed")
    let ptx = p.tx.get()
    # Choose the highest version number.
    if uint32(ptx.version) > bestVersion:
      bestVersion = uint32(ptx.version)
    # Choose the lowest lock time.
    if ptx.lockTime < bestLocktime:
      bestLocktime = ptx.lockTime
    psbtxs.add(p)

  # Build the merged PSBT, deduplicating inputs by prevout (txid:vout).
  var merged: Psbt
  merged.tx = some(Transaction(
    version: int32(bestVersion),
    inputs: @[],
    outputs: @[],
    witnesses: @[],
    lockTime: bestLocktime))

  var seenInputs = initHashSet[(TxId, uint32)]()
  for p in psbtxs:
    let ptx = p.tx.get()
    for i in 0 ..< ptx.inputs.len:
      let op = ptx.inputs[i].prevOut
      let key = (op.txid, op.vout)
      if key in seenInputs:
        # Core: RPC_INVALID_PARAMETER (-8) "Input <txid>:<n> exists in
        # multiple PSBTs". `$op.txid` renders big-endian (Core ToString()).
        raise newRpcError(RpcInvalidParameter,
          "Input " & $op.txid & ":" & $op.vout & " exists in multiple PSBTs")
      seenInputs.incl(key)
      merged.addInput(ptx.inputs[i], p.inputs[i])
    for i in 0 ..< ptx.outputs.len:
      merged.addOutput(ptx.outputs[i], p.outputs[i])
    # Merge global xpubs.
    for origin, xpubs in p.xpubs:
      if origin notin merged.xpubs:
        merged.xpubs[origin] = initHashSet[seq[byte]]()
      for xpub in xpubs:
        merged.xpubs[origin].incl(xpub)
    # Merge unknown global map.
    for k, v in p.unknown:
      if k notin merged.unknown:
        merged.unknown[k] = v

  # Shuffle inputs and outputs for privacy parity (Core std::shuffle with
  # FastRandomContext). Result is order-randomized; compare as sets.
  let mtx = merged.tx.get()
  let inOrder = shufflePsbtIndices(mtx.inputs.len)
  let outOrder = shufflePsbtIndices(mtx.outputs.len)

  var shuffled: Psbt
  shuffled.tx = some(Transaction(
    version: mtx.version,
    inputs: @[],
    outputs: @[],
    witnesses: @[],
    lockTime: mtx.lockTime))
  shuffled.xpubs = merged.xpubs
  shuffled.unknown = merged.unknown
  for idx in inOrder:
    shuffled.addInput(mtx.inputs[idx], merged.inputs[idx])
  for idx in outOrder:
    shuffled.addOutput(mtx.outputs[idx], merged.outputs[idx])

  %shuffled.toBase64()

proc handleFinalizePsbt(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Finalize the inputs of a PSBT
  ## Reference: Bitcoin Core rpc/rawtransaction.cpp finalizepsbt
  ##
  ## Arguments:
  ## 1. psbt (string, required) - Base64-encoded PSBT
  ## 2. extract (bool, optional, default=true) - If true, extract and return complete tx
  ##
  ## Returns: Object with:
  ## - psbt: Finalized base64 PSBT (if not extractable)
  ## - hex: Raw transaction hex (if extract=true and complete)
  ## - complete: Whether all inputs are finalized

  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing psbt parameter")

  let psbtBase64 = params[0].getStr()
  let extract = if params.len >= 2 and params[1].kind != JNull: params[1].getBool() else: true

  var psbtObj: Psbt
  try:
    psbtObj = fromBase64(psbtBase64)
  except PsbtError as e:
    raise newRpcError(RpcInvalidParams, "invalid PSBT: " & e.msg)
  except CatchableError as e:
    raise newRpcError(RpcInvalidParams, "invalid PSBT: " & e.msg)

  # Attempt to finalize all inputs
  let complete = finalizePsbt(psbtObj)

  result = newJObject()
  result["complete"] = %complete

  if complete and extract:
    # Extract complete transaction
    let txOpt = extractTransaction(psbtObj)
    if txOpt.isSome:
      let tx = txOpt.get()
      result["hex"] = %toHex(serialize(tx))
    else:
      # Shouldn't happen if complete=true, but handle gracefully
      result["psbt"] = %psbtObj.toBase64()
  else:
    result["psbt"] = %psbtObj.toBase64()

proc handleAnalyzePsbt(rpc: RpcServer, params: JsonNode): JsonNode =
  ## analyzepsbt: analyse a PSBT and report next-role per input + globally.
  ##
  ## Output shape mirrors Bitcoin Core's `analyzepsbt`
  ## (`bitcoin-core/src/rpc/rawtransaction.cpp::analyzepsbt`,
  ## `bitcoin-core/src/node/psbt.cpp::AnalyzePSBT`):
  ##
  ##   {
  ##     "inputs": [
  ##       { "has_utxo": bool, "is_final": bool, "next": role,
  ##         "missing": { "signatures": ["pubkey-hex", ...] }  (optional) },
  ##       ...
  ##     ],
  ##     "next": role
  ##   }
  ##
  ## PSBT-level `next` is the min per-input role under Core's order
  ## (creator < updater < signer < finalizer < extractor; see
  ## `bitcoin-core/src/node/psbt.cpp:91-95`). Multisig inputs are
  ## classified by parsing the redeem/witness CHECKMULTISIG layout to
  ## derive the M threshold; an input with M partial sigs is reported as
  ## "finalizer" (closes W41 / W47-5: any-sig-means-signer regression).
  ##
  ## Reference: hotbuns W47-5 (`b6ccf2a`) `analyzePSBTCore`.
  ## Reference: camlcoin W41 (`2a22a0e`) `psbt_next_role`.

  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing psbt parameter")

  let psbtBase64 = params[0].getStr()

  var psbtObj: Psbt
  try:
    psbtObj = fromBase64(psbtBase64)
  except PsbtError as e:
    raise newRpcError(RpcInvalidParams, "invalid PSBT: " & e.msg)
  except CatchableError as e:
    raise newRpcError(RpcInvalidParams, "invalid PSBT: " & e.msg)

  let analysis = analyzePsbtCore(psbtObj)

  result = newJObject()
  var inputsJson = newJArray()
  for ai in analysis.inputs:
    var inp = newJObject()
    inp["has_utxo"] = %ai.hasUtxo
    inp["is_final"] = %ai.isFinal
    inp["next"] = %ai.nextRole
    if ai.missingSignatures.len > 0:
      var miss = newJObject()
      var sigs = newJArray()
      for pk in ai.missingSignatures:
        sigs.add(%toHex(pk))
      miss["signatures"] = sigs
      inp["missing"] = miss
    inputsJson.add(inp)
  result["inputs"] = inputsJson
  result["next"] = %analysis.nextRole

# ============================================================================
# Wave-47b P2 RPCs
# Reference: Bitcoin Core src/rpc/blockchain.cpp + src/rpc/mining.cpp
# ============================================================================

proc w47bDsha256(data: openArray[byte]): array[32, byte] =
  sha256d(data)

proc w47bDsha256Pair(a, b: array[32, byte]): array[32, byte] =
  var combined: array[64, byte]
  for i in 0..31: combined[i] = a[i]
  for i in 0..31: combined[32 + i] = b[i]
  sha256d(combined)

proc w47bTreeWidth(nTx, height: int): int =
  (nTx + (1 shl height) - 1) shr height

proc w47bCalcTreeHash(txids: seq[array[32, byte]], nTx, height, pos: int): array[32, byte] =
  if height == 0:
    if pos < nTx: return txids[pos]
    return default(array[32, byte])
  let left = w47bCalcTreeHash(txids, nTx, height - 1, pos * 2)
  let rightPos = pos * 2 + 1
  let right = if rightPos < w47bTreeWidth(nTx, height - 1):
    w47bCalcTreeHash(txids, nTx, height - 1, rightPos)
  else:
    left
  w47bDsha256Pair(left, right)

proc w47bEncodeVarInt(n: int): seq[byte] =
  if n < 0xFD:
    @[byte(n)]
  elif n <= 0xFFFF:
    let v = uint16(n)
    @[byte(0xFD), byte(v and 0xFF), byte(v shr 8)]
  elif n <= 0xFFFFFFFF:
    let v = uint32(n)
    @[byte(0xFE), byte(v and 0xFF), byte((v shr 8) and 0xFF),
      byte((v shr 16) and 0xFF), byte(v shr 24)]
  else:
    let v = uint64(n)
    @[byte(0xFF), byte(v and 0xFF), byte((v shr 8) and 0xFF),
      byte((v shr 16) and 0xFF), byte((v shr 24) and 0xFF),
      byte((v shr 32) and 0xFF), byte((v shr 40) and 0xFF),
      byte((v shr 48) and 0xFF), byte(v shr 56)]

proc w47bBuildPartialMerkleTree(
    headerBytes: array[80, byte],
    txids: seq[array[32, byte]],
    matches: seq[bool]): seq[byte] =
  let n = txids.len
  var height = 0
  while (1 shl height) < n: inc height

  var hashes: seq[array[32, byte]]
  var bits: seq[bool]

  proc traverse(h, pos: int) =
    let start = pos shl h
    let endRaw = (pos + 1) shl h
    let endPos = min(endRaw, n)
    var parentMatch = false
    for i in start ..< endPos:
      if matches[i]: parentMatch = true; break
    bits.add(parentMatch)
    if h == 0 or not parentMatch:
      if h == 0:
        hashes.add(if pos < n: txids[pos] else: default(array[32, byte]))
      else:
        hashes.add(w47bCalcTreeHash(txids, n, h, pos))
    else:
      traverse(h - 1, pos * 2)
      if pos * 2 + 1 < w47bTreeWidth(n, h - 1):
        traverse(h - 1, pos * 2 + 1)

  traverse(height, 0)

  result = @[]
  for b in headerBytes: result.add(b)
  result.add(byte(n and 0xFF))
  result.add(byte((n shr 8) and 0xFF))
  result.add(byte((n shr 16) and 0xFF))
  result.add(byte(n shr 24))
  result.add(w47bEncodeVarInt(hashes.len))
  for h32 in hashes:
    for b in h32: result.add(b)
  let flagCount = (bits.len + 7) div 8
  result.add(w47bEncodeVarInt(flagCount))
  var flagBytes = newSeq[byte](flagCount)
  for i, b in bits:
    if b: flagBytes[i div 8] = flagBytes[i div 8] or byte(1 shl (i mod 8))
  result.add(flagBytes)

proc w47bReadVarInt(data: seq[byte], offset: int): tuple[val: int, next: int] =
  if offset >= data.len: return (0, offset)
  let first = data[offset]
  if first == 0xFD:
    if offset + 3 > data.len: return (0, data.len)
    let v = int(data[offset+1]) or (int(data[offset+2]) shl 8)
    return (v, offset + 3)
  elif first == 0xFE:
    if offset + 5 > data.len: return (0, data.len)
    let v = int(data[offset+1]) or (int(data[offset+2]) shl 8) or
            (int(data[offset+3]) shl 16) or (int(data[offset+4]) shl 24)
    return (v, offset + 5)
  elif first == 0xFF:
    if offset + 9 > data.len: return (0, data.len)
    let v = int(data[offset+1]) or (int(data[offset+2]) shl 8) or
            (int(data[offset+3]) shl 16) or (int(data[offset+4]) shl 24)
    return (v, offset + 9)
  else:
    return (int(first), offset + 1)

proc w47bParsePartialMerkleTree(data: seq[byte]): tuple[matched: seq[array[32, byte]], root: array[32, byte]] =
  if data.len < 4:
    raise newRpcError(RpcMiscError, "Proof payload too short")
  let nTx = int(data[0]) or (int(data[1]) shl 8) or (int(data[2]) shl 16) or (int(data[3]) shl 24)
  var offset = 4

  let (nHashes, off1) = w47bReadVarInt(data, offset)
  offset = off1

  var hashes: seq[array[32, byte]]
  for _ in 0 ..< nHashes:
    if offset + 32 > data.len:
      raise newRpcError(RpcMiscError, "Proof truncated in hashes")
    var h: array[32, byte]
    for i in 0..31: h[i] = data[offset + i]
    hashes.add(h)
    offset += 32

  let (nFlagBytes, off2) = w47bReadVarInt(data, offset)
  offset = off2
  if offset + nFlagBytes > data.len:
    raise newRpcError(RpcMiscError, "Proof truncated in flags")
  var allBits: seq[bool]
  for i in 0 ..< nFlagBytes:
    for bit in 0..7:
      allBits.add((data[offset + i] and byte(1 shl bit)) != 0)

  var treeHeight = 0
  while (1 shl treeHeight) < nTx: inc treeHeight

  var hashIdx = 0
  var bitIdx = 0
  var matched: seq[array[32, byte]]

  proc consume(h, pos: int): array[32, byte] =
    if bitIdx >= allBits.len:
      raise newRpcError(RpcMiscError, "Bits exhausted in proof")
    let parentMatch = allBits[bitIdx]
    inc bitIdx
    if h == 0:
      let cur = if hashIdx < hashes.len: hashes[hashIdx] else: default(array[32, byte])
      inc hashIdx
      if parentMatch: matched.add(cur)
      return cur
    if not parentMatch:
      let cur = if hashIdx < hashes.len: hashes[hashIdx] else: default(array[32, byte])
      inc hashIdx
      return cur
    let left = consume(h - 1, pos * 2)
    let rightPos = pos * 2 + 1
    let right = if rightPos < w47bTreeWidth(nTx, h - 1):
      consume(h - 1, rightPos)
    else:
      left
    w47bDsha256Pair(left, right)

  let computedRoot = consume(treeHeight, 0)
  (matched, computedRoot)

proc handleGetNetworkHashPS(rpc: RpcServer, params: JsonNode): JsonNode =
  var nblocks: int32 = 120
  var targetHeight: int32 = -1
  if params.kind == JArray:
    if params.len >= 1 and params[0].kind == JInt:
      nblocks = int32(params[0].getInt())
    if params.len >= 2 and params[1].kind == JInt:
      targetHeight = int32(params[1].getInt())
  let bestHeight = rpc.chainState.bestHeight
  var tipH: int32 = bestHeight
  if targetHeight >= 0 and targetHeight <= bestHeight:
    tipH = targetHeight
  if nblocks <= 0:
    nblocks = tipH mod 2016
    if nblocks == 0: nblocks = 1
  if nblocks > tipH: nblocks = tipH
  if nblocks == 0 or tipH == 0: return %0.0
  let startH: int32 = tipH - nblocks
  let tipHashOpt = rpc.chainState.db.getBlockHashByHeight(tipH)
  let startHashOpt = rpc.chainState.db.getBlockHashByHeight(startH)
  if tipHashOpt.isNone or startHashOpt.isNone: return %0.0
  let tipIdxOpt = rpc.chainState.db.getBlockIndex(tipHashOpt.get())
  let startIdxOpt = rpc.chainState.db.getBlockIndex(startHashOpt.get())
  if tipIdxOpt.isNone or startIdxOpt.isNone: return %0.0
  let tipIdx = tipIdxOpt.get()
  let startIdx = startIdxOpt.get()
  let timeDiff = int64(tipIdx.header.timestamp) - int64(startIdx.header.timestamp)
  if timeDiff <= 0: return %0.0
  # totalWork is stored LITTLE-ENDIAN (byte 0 = LSB; see calculateWork in
  # network/sync.nim — carry propagates low->high — and the LE summation in
  # storage/chainstate.nim). The previous loop read bytes 24..31 as if the
  # array were big-endian; those are the all-zero HIGH bytes for any realistic
  # work value, so tipWork==startWork==0 and the result was ALWAYS 0.0.
  # Read the full 256-bit magnitude as a float64 (ample range for 2^256≈1e77),
  # matching Core's arith_uint256 (work_tip - work_start) / time. Network-
  # agnostic: no 64-bit truncation that the old uint64 path would suffer on
  # high-work chains.
  var tipWorkF: float64 = 0.0
  var startWorkF: float64 = 0.0
  for i in countdown(31, 0):
    tipWorkF = tipWorkF * 256.0 + float64(tipIdx.totalWork[i])
    startWorkF = startWorkF * 256.0 + float64(startIdx.totalWork[i])
  if tipWorkF <= startWorkF: return %0.0
  %((tipWorkF - startWorkF) / float64(timeDiff))

proc handleGetTxOutProof(rpc: RpcServer, params: JsonNode): JsonNode =
  if params.kind != JArray or params.len < 1:
    raise newRpcError(RpcInvalidParams, "Expected [txids, (blockhash)]")
  let txidsArr = params[0]
  if txidsArr.kind != JArray or txidsArr.len == 0:
    raise newRpcError(RpcInvalidParams, "txids must be a non-empty array")
  var targetTxids: seq[array[32, byte]]
  for item in txidsArr:
    if item.kind != JString or item.getStr().len != 64:
      raise newRpcError(RpcInvalidParams, "txid must be a 64-char hex string")
    targetTxids.add(array[32, byte](parseTxId(item.getStr())))
  var blkOpt: Option[Block]
  var blkHeader: BlockHeader
  if params.len >= 2:
    let bhStr = params[1].getStr()
    # Core ParseHashV: malformed blockhash -> -8 before lookup (was -32602 for
    # wrong-length, -32603 for a 64-char non-hex). Unknown stays -5 below.
    validateHashV(bhStr, "blockhash")
    let bh = parseBlockHash(bhStr)
    blkOpt = rpc.chainState.db.getBlock(bh)
    if blkOpt.isNone: raise newRpcError(RpcInvalidAddressOrKey, "Block not found")
    blkHeader = blkOpt.get().header
  else:
    let tipHeight = rpc.chainState.bestHeight
    let searchStart = if tipHeight >= 100: tipHeight - 100 else: 0
    var h = tipHeight
    while h >= searchStart:
      let hashOpt = rpc.chainState.db.getBlockHashByHeight(h)
      if hashOpt.isSome:
        let candidate = rpc.chainState.db.getBlock(hashOpt.get())
        if candidate.isSome:
          let blk = candidate.get()
          var found = false
          for tx in blk.txs:
            let txid = array[32, byte](tx.txid())
            for target in targetTxids:
              if txid == target: found = true; break
            if found: break
          if found:
            blkOpt = candidate
            blkHeader = blk.header
            break
      if h == 0: break
      dec h
    if blkOpt.isNone:
      raise newRpcError(RpcInvalidAddressOrKey, "Transaction not found in recent blocks")
  let blk = blkOpt.get()
  var allTxids: seq[array[32, byte]]
  var matches: seq[bool]
  for tx in blk.txs:
    let txid = array[32, byte](tx.txid())
    allTxids.add(txid)
    var isTarget = false
    for t in targetTxids:
      if txid == t: isTarget = true; break
    matches.add(isTarget)
  for target in targetTxids:
    var found = false
    for txid in allTxids:
      if txid == target: found = true; break
    if not found: raise newRpcError(RpcInvalidParams, "Transaction not found in block")
  var w = BinaryWriter()
  w.writeBlockHeader(blkHeader)
  var headerBytes: array[80, byte]
  for i in 0..79: headerBytes[i] = w.data[i]
  let proofBytes = w47bBuildPartialMerkleTree(headerBytes, allTxids, matches)
  %toHex(proofBytes)

proc handleVerifyTxOutProof(rpc: RpcServer, params: JsonNode): JsonNode =
  if params.kind != JArray or params.len < 1 or params[0].kind != JString:
    raise newRpcError(RpcInvalidParams, "Expected [proof_hex]")
  let hexStr = params[0].getStr()
  if hexStr.len < 168 or hexStr.len mod 2 != 0:
    raise newRpcError(RpcMiscError, "Proof too short")
  let proofBytes = hexToBytes(hexStr)
  if proofBytes.len < 84: raise newRpcError(RpcMiscError, "Proof too short")
  let blockHashBytes = w47bDsha256(proofBytes[0..79])
  let blockHash = BlockHash(blockHashBytes)
  let idxOpt = rpc.chainState.db.getBlockIndex(blockHash)
  if idxOpt.isNone: raise newRpcError(RpcInvalidAddressOrKey, "Block not in chain")
  var merkleRootInHeader: array[32, byte]
  for i in 0..31: merkleRootInHeader[i] = proofBytes[36 + i]
  let payload = proofBytes[80 .. proofBytes.high]
  let (matched, computedRoot) = w47bParsePartialMerkleTree(payload)
  if computedRoot != merkleRootInHeader:
    raise newRpcError(RpcMiscError, "Merkle root mismatch")
  var resultArr = newJArray()
  for txid in matched:
    var display: array[32, byte] = txid
    for i in 0..15: swap(display[i], display[31 - i])
    resultArr.add(%toHex(display))
  resultArr

proc handleGetRPCInfo(rpc: RpcServer): JsonNode =
  discard rpc
  %*{"active_commands": [], "logpath": ""}

# ---------------------------------------------------------------------------
# Wait-family RPCs: waitfornewblock / waitforblock / waitforblockheight
#
# Bitcoin Core rpc/blockchain.cpp lines 290-470. Block until the active-chain
# tip satisfies a predicate (new tip / hash match / height >=) OR a millisecond
# timeout elapses, then return the CURRENT tip {hash, height} in either case.
# Mirrors the proven ouroboros pilot (src/ouroboros/rpc.py _wait_for_tip + the
# three handlers), which byte-matched live Core.
#
# These are async (they await the cross-thread TipNotifier on the RPC thread's
# chronos loop), unlike the synchronous handleMethod dispatch — so they are
# routed by asyncHandleRequest below, before the synchronous case-dispatch.
# ---------------------------------------------------------------------------

proc currentTipDisplay(rpc: RpcServer): tuple[hash: string, height: int32] =
  ## Authoritative active-chain tip, display (big-endian hex) form. Re-read on
  ## every wait wake so a coalesced / missed notify can never yield a wrong
  ## answer (Core reads ActiveChain().Tip() each loop iteration).
  let h = reverseHex(toHex(array[32, byte](rpc.chainState.bestBlockHash)))
  (h, rpc.chainState.bestHeight)

proc parseWaitTimeoutMs(params: JsonNode, idx: int): int =
  ## Read the `timeout` arg (Core getInt<int>(): non-integral -> RPC_TYPE_ERROR
  ## -3; negative -> RPC_MISC_ERROR -1 "Negative timeout"). Absent / null = 0
  ## (no timeout). Returns milliseconds.
  if params.kind != JArray or idx >= params.len or params[idx].kind == JNull:
    return 0
  let t = params[idx]
  if t.kind != JInt:
    raise newRpcError(RpcTypeError,
      "JSON value of type " & (
        case t.kind
        of JString: "string"
        of JFloat: "number"
        of JBool: "bool"
        of JObject: "object"
        of JArray: "array"
        else: "null"
      ) & " is not of expected type number")
  let ms = t.getInt()
  if ms < 0:
    raise newRpcError(RpcMiscError, "Negative timeout")
  ms

proc parseWaitHeight(params: JsonNode, idx: int): int =
  ## Read the `height` arg for waitforblockheight (Core getInt<int>(): a
  ## non-integral height -> RPC_TYPE_ERROR -3). Required (no default).
  if params.kind != JArray or idx >= params.len or params[idx].kind == JNull:
    raise newRpcError(RpcTypeError,
      "JSON value of type null is not of expected type number")
  let h = params[idx]
  if h.kind != JInt:
    raise newRpcError(RpcTypeError,
      "JSON value of type " & (
        case h.kind
        of JString: "string"
        of JFloat: "number"
        of JBool: "bool"
        of JObject: "object"
        of JArray: "array"
        else: "null"
      ) & " is not of expected type number")
  h.getInt()

proc waitForTip(rpc: RpcServer,
                predicate: proc(displayHash: string, height: int32): bool {.gcsafe, raises: [].},
                timeoutMs: int): Future[JsonNode] {.async.} =
  ## Core's wait-tip-changed loop (rpc/blockchain.cpp) shared by all three
  ## wait-family RPCs. Returns the current tip {hash, height} once `predicate`
  ## holds OR `timeoutMs` (0 = no timeout) elapses — Core returns the current
  ## block in both cases. Re-reads the AUTHORITATIVE tip on every wake.
  var (displayHash, height) = rpc.currentTipDisplay()
  if predicate(displayHash, height):
    return %*{"hash": displayHash, "height": height}

  let notifier = rpc.tipNotifier
  if notifier == nil:
    # No notifier wired (degraded boot): cannot block on tip changes; return
    # the current tip rather than hang. Defensive fallback only.
    return %*{"hash": displayHash, "height": height}

  # Absolute deadline in monotonic milliseconds (integer math avoids the
  # std/times vs chronos `milliseconds` symbol clash). Unused when timeoutMs==0.
  let deadlineMs = monotonicMs() + timeoutMs.int64

  while true:
    # Snapshot the generation BEFORE re-checking the predicate so a notify that
    # races in between the check and the await is observed (no lost wakeup).
    let gen = notifier.generation()
    (displayHash, height) = rpc.currentTipDisplay()
    if predicate(displayHash, height):
      return %*{"hash": displayHash, "height": height}

    var sliceMs = timeoutMs
    if timeoutMs > 0:
      let remaining = deadlineMs - monotonicMs()
      if remaining <= 0:
        # Timed out — return the current tip (Core's behaviour).
        return %*{"hash": displayHash, "height": height}
      sliceMs = int(remaining)

    discard await notifier.waitTipChanged(gen, sliceMs)

proc rpcWaitForNewBlock(rpc: RpcServer, params: JsonNode): Future[JsonNode] {.async.} =
  ## Core waitfornewblock(timeout=0, current_tip?). Wait until the tip differs
  ## from `current_tip` (or, if omitted, the tip at call entry); return the tip.
  ## `timeout` is milliseconds (0 = no timeout). On timeout returns current tip.
  let timeoutMs = parseWaitTimeoutMs(params, 0)

  # Reference hash the new tip must differ from. When current_tip is supplied
  # it is parsed as a 64-hex uint256 (Core ParseHashV("current_tip") -> -8 on
  # malformed). When omitted, snapshot the live tip.
  var refHash: string
  if params.kind == JArray and params.len > 1 and params[1].kind != JNull:
    let ct = params[1]
    if ct.kind != JString:
      raise newRpcError(RpcInvalidParameter,
        "current_tip must be hexadecimal string (not '" & $ct & "')")
    validateHashV(ct.getStr(), "current_tip")
    refHash = ct.getStr().toLowerAscii()
  else:
    let (h, _) = rpc.currentTipDisplay()
    refHash = h

  let p = proc(displayHash: string, height: int32): bool {.gcsafe, raises: [].} =
    displayHash.toLowerAscii() != refHash
  return await rpc.waitForTip(p, timeoutMs)

proc rpcWaitForBlock(rpc: RpcServer, params: JsonNode): Future[JsonNode] {.async.} =
  ## Core waitforblock(blockhash, timeout=0). Wait until the tip's hash equals
  ## `blockhash`; return the tip. `blockhash` is parsed FIRST (Core parses it
  ## before reading timeout), so a malformed blockhash errors -8 even when a
  ## negative timeout is also supplied. `timeout` is milliseconds (0 = none).
  if params.kind != JArray or params.len < 1 or params[0].kind == JNull:
    raise newRpcError(RpcInvalidParameter,
      "blockhash must be hexadecimal string (not 'null')")
  let bh = params[0]
  if bh.kind != JString:
    raise newRpcError(RpcInvalidParameter,
      "blockhash must be hexadecimal string (not '" & $bh & "')")
  validateHashV(bh.getStr(), "blockhash")
  let target = bh.getStr().toLowerAscii()

  # Parsed AFTER blockhash (Core order).
  let timeoutMs = parseWaitTimeoutMs(params, 1)

  let p = proc(displayHash: string, height: int32): bool {.gcsafe, raises: [].} =
    displayHash.toLowerAscii() == target
  return await rpc.waitForTip(p, timeoutMs)

proc rpcWaitForBlockHeight(rpc: RpcServer, params: JsonNode): Future[JsonNode] {.async.} =
  ## Core waitforblockheight(height, timeout=0). Wait until the tip height >=
  ## `height`; return the tip. `height` is read as an int (non-int -> -3).
  ## `timeout` is milliseconds (0 = no timeout). On timeout returns current tip.
  let targetHeight = parseWaitHeight(params, 0)
  let timeoutMs = parseWaitTimeoutMs(params, 1)

  let p = proc(displayHash: string, height: int32): bool {.gcsafe, raises: [].} =
    int(height) >= targetHeight
  return await rpc.waitForTip(p, timeoutMs)

proc handleVerifyChain(rpc: RpcServer, params: JsonNode): JsonNode =
  ## verifychain ( checklevel nblocks )
  ##
  ## Re-validates the last `nblocks` blocks of the active chain at the requested
  ## `checklevel`, returning a JSON bool (true = all checks passed). This is the
  ## nimrod analog of Bitcoin Core CVerifyDB::VerifyDB
  ## (bitcoin-core/src/validation.cpp:4611) called from the verifychain RPC
  ## (bitcoin-core/src/rpc/blockchain.cpp:1262).
  ##
  ## Arguments (positional, both optional):
  ##   1. checklevel (int, default 3, clamped to 0..4) — how thorough:
  ##        0  read block from disk (ReadBlock)
  ##        1  + CheckBlock          (real context-free validation)
  ##        2  + read & decode undo  (ReadBlockUndo + tx-count consistency)
  ##        3  + disconnect-tip      (in-memory DisconnectBlock consistency)
  ##        4  + reconnect           (real ConnectBlock-equivalent: full script
  ##                                  verification via validateBlock)
  ##   2. nblocks (int, default 6; 0 or > chain-height means ALL blocks)
  ##
  ## CRITICAL: this MUST NOT mutate the live chainstate. Core's VerifyDB works on
  ## a throwaway CCoinsViewCache layered over the real coins view; nimrod mirrors
  ## that with an in-memory `overlay` over `cs.getUtxo`. The live UTXO set, the
  ## RocksDB block index, and the undo files are only ever READ. Levels 3 and 4
  ## reconstruct the fork-point UTXO view by replaying each block's stored undo
  ## into the overlay (disconnect) and then re-run validateBlock against that
  ## overlay (reconnect) — the exact same CheckBlock/ConnectBlock machinery the
  ## node uses during sync, never a constant-true stub.
  let cs = rpc.chainState

  # Core: const int check_level{params[0].isNull() ? DEFAULT_CHECKLEVEL : ...};
  #       const int check_depth{params[1].isNull() ? DEFAULT_CHECKBLOCKS : ...};
  var checkLevel = 3
  if params.kind == JArray and params.len >= 1 and params[0].kind != JNull:
    checkLevel = params[0].getInt()
  var nBlocks = 6
  if params.kind == JArray and params.len >= 2 and params[1].kind != JNull:
    nBlocks = params[1].getInt()

  # nCheckLevel = std::max(0, std::min(4, nCheckLevel));  (validation.cpp:4627)
  checkLevel = max(0, min(4, checkLevel))

  let tipHeight = cs.bestHeight

  # Core: if chain tip is null or tip->pprev is null, return SUCCESS
  # (validation.cpp:4619). Genesis-only or empty chain → nothing to verify.
  if tipHeight <= 0:
    return %true

  # if (nCheckDepth <= 0 || nCheckDepth > chain.Height()) nCheckDepth = Height();
  # (validation.cpp:4624). 0 = all; clamp to the chain height.
  var checkDepth = nBlocks
  if checkDepth <= 0 or checkDepth > tipHeight:
    checkDepth = tipHeight

  let startHeight = tipHeight - checkDepth + 1  # inclusive lower bound
  info "verifychain: verifying blocks", lastN = checkDepth, level = checkLevel,
       fromHeight = startHeight, toHeight = tipHeight

  # In-memory sandbox UTXO view layered over the live coins view. value == none
  # marks an outpoint as spent/absent in the sandbox; a present value shadows
  # the live entry. Reads fall through to cs.getUtxo. Mutated ONLY in this proc.
  var overlay = initTable[OutPoint, Option[UtxoEntry]]()

  proc sandboxGetUtxo(op: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].} =
    if overlay.hasKey(op):
      try:
        return overlay[op]
      except KeyError:
        discard  # unreachable: hasKey guaranteed membership above
    try:
      return cs.getUtxo(op)
    except CatchableError:
      return none(UtxoEntry)

  # Stack of (block, prevIndex, height) for the disconnected range, so level 4
  # can re-connect bottom-up (oldest first), exactly like Core's reconnect loop
  # (validation.cpp:4716-4737 walks chain.Next(pindex) upward to the tip).
  var disconnected: seq[tuple[blk: Block, prevIdx: BlockIndex, height: int32]] = @[]

  # ---- Levels 0-3: walk DOWN from the tip (disconnect direction) ----------
  var h = tipHeight
  while h >= startHeight and h >= 1:
    let hashOpt = cs.db.getBlockHashByHeight(h)
    if hashOpt.isNone:
      warn "verifychain: missing height->hash mapping", height = h
      return %false
    let blockHash = hashOpt.get()

    let idxOpt = cs.db.getBlockIndex(blockHash)
    if idxOpt.isNone:
      warn "verifychain: missing block index", height = h
      return %false
    let idx = idxOpt.get()

    # Level 0: ReadBlock from disk (read + deserialize).
    let blkOpt = cs.db.getBlock(blockHash)
    if blkOpt.isNone:
      error "verifychain: ReadBlock failed", height = h, hash = $blockHash
      return %false
    let blk = blkOpt.get()

    # Level 1: CheckBlock — the real context-free validator (PoW, merkle root,
    # tx sanity, witness commitment). validation.cpp:4666.
    if checkLevel >= 1:
      let cbRes = checkBlock(blk, cs.params)
      if not cbRes.isOk:
        error "verifychain: found bad block (CheckBlock)", height = h,
              hash = $blockHash, reason = $cbRes.error
        return %false

    # Read this block's prevIndex once (needed for level-4 validateBlock, and to
    # build the parent header context). The parent is at height h-1.
    let prevIdxOpt = cs.db.getBlockIndex(idx.prevHash)
    var prevIdx: BlockIndex
    if prevIdxOpt.isSome:
      prevIdx = prevIdxOpt.get()
    else:
      # Genesis parent sentinel (height -1). Only reachable if startHeight==1
      # and the parent is genesis whose index row may be a header-only stub.
      prevIdx = BlockIndex(height: h - 1, hash: idx.prevHash)

    # Level 2: read + decode the undo data (ReadBlockUndo) and check the
    # block/undo tx-count consistency. validation.cpp:4672-4680.
    var blockUndoOpt = none(BlockUndo)
    if checkLevel >= 2:
      blockUndoOpt = cs.getBlockUndoFromFile(idx, idx.prevHash)
      # A non-coinbase-bearing block MUST have undo data on the active chain.
      # (Genesis is excluded — h >= 1 here, but a coinbase-only block legitimately
      #  has an empty undo set.)
      if blk.txs.len > 1 and blockUndoOpt.isNone:
        error "verifychain: found bad undo data (missing/undecodable)",
              height = h, hash = $blockHash
        return %false
      if blockUndoOpt.isSome:
        # One TxUndo per non-coinbase tx (Core validation.cpp:2190-2193).
        if blockUndoOpt.get().txUndo.len + 1 != blk.txs.len:
          error "verifychain: undo/block tx-count mismatch", height = h,
                hash = $blockHash, undoEntries = blockUndoOpt.get().txUndo.len,
                blockTxs = blk.txs.len
          return %false

    # Level 3: in-memory disconnect into the sandbox overlay, REUSING the SAME
    # coin-level rewind machinery the production reorg path runs
    # (chainstate.disconnectBlockIntoView — a faithful port of Core
    # DisconnectBlock, validation.cpp:2179-2248). There is no verifychain-only
    # disconnect copy: the undo conversion (blockUndoToUndoData) and the
    # reverse-order SpendCoin/ApplyTxInUndo loop are exactly what
    # `disconnectBlock(cs, blk)` uses during a real reorg — here they are driven
    # against the in-memory overlay (NEVER live chainstate).
    #
    # The old hand-rolled copy walked transactions FORWARD and treated a
    # legitimately-absent created output as fatal, so any block carrying an
    # intra-block (chained / CPFP) spend — where a later tx consumes an output
    # an earlier tx in the SAME block created — failed L3. Coinbase-only regtest
    # never exercised it; real mainnet blocks do, which is why the live L3 spot
    # check returned false. Reverse-order disconnect restores the intermediate
    # output (via the later tx's undo) before the earlier tx removes it, so a
    # valid chain disconnects cleanly (DISCONNECT_OK).
    if checkLevel >= 3:
      # Convert the L2-decoded BlockUndo into the per-(tx,vin)-aligned UndoData
      # via the shared converter (same gates the reorg path applies).
      var undoData = UndoData()
      if blockUndoOpt.isSome:
        let undoConv = blockUndoToUndoData(blk, blockUndoOpt.get())
        if not undoConv.isOk:
          error "verifychain: irrecoverable inconsistency (undo conversion)",
                height = h, hash = $blockHash, reason = undoConv.error
          return %false
        undoData = undoConv.value

      # Overlay-backed view callbacks. value==none marks an outpoint spent/absent
      # in the sandbox; a present value shadows the live entry. Reads fall
      # through to the live coins view via sandboxGetUtxo. Writes touch ONLY the
      # in-memory overlay.
      let viewGet = proc(op: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].} =
        sandboxGetUtxo(op)
      let viewSet = proc(op: OutPoint, entry: Option[UtxoEntry]) {.gcsafe, raises: [].} =
        overlay[op] = entry

      let dr = disconnectBlockIntoView(blk, h, blockHash, undoData, viewGet, viewSet)
      # Core VerifyDB level 3: DISCONNECT_FAILED -> CORRUPTED_BLOCK_DB; a
      # DISCONNECT_UNCLEAN sets pindexFailure which ALSO returns CORRUPTED_BLOCK_DB
      # at the end of VerifyDB (validation.cpp:4688-4694, 4704-4706). Only a clean
      # disconnect (drOk) is accepted — exactly Core's pindexFailure semantics.
      if dr != drOk:
        error "verifychain: irrecoverable inconsistency on disconnect",
              height = h, hash = $blockHash, result = $dr
        return %false

      # Remember this block for the reconnect pass (level 4).
      disconnected.add((blk, prevIdx, h))

    dec h

  # ---- Level 4: walk UP (reconnect direction), full re-validation ----------
  # The overlay now represents the UTXO set as it was at startHeight-1 (the fork
  # point). Re-run validateBlock with checkScripts=true bottom-up — the SAME
  # ConnectBlock-equivalent machinery used during sync, including every input
  # script verification. validation.cpp:4716-4737.
  if checkLevel >= 4:
    for i in countdown(disconnected.len - 1, 0):
      let (blk, prevIdx, height) = disconnected[i]
      let res = validateBlock(blk, prevIdx, cs.db, cs.params,
                              checkScripts = true,
                              checkPow = true,
                              getUtxoOverride = sandboxGetUtxo)
      if not res.isOk:
        let bh = BlockHash(doubleSha256(serialize(blk.header)))
        error "verifychain: found unconnectable block (ConnectBlock)",
              height = height, hash = $bh, reason = $res.error
        return %false

      # Level 4 script verification: call verifyScripts separately, mirroring
      # the sync path at validation.nim:2320 (acceptBlock step 4). validateBlock's
      # checkScripts parameter is dead code -- verifyScripts is the real verifier.
      # Core CVerifyDB::VerifyDB level 4 runs full ConnectBlock incl scripts.
      let scriptRes = verifyScripts(blk, sandboxGetUtxo, height, rpc.crypto, cs.params)
      if not scriptRes.isOk:
        let bh2 = BlockHash(doubleSha256(serialize(blk.header)))
        error "verifychain: found block with invalid scripts (verifyScripts)",
              height = height, hash = $bh2, reason = $scriptRes.error
        return %false

      # Apply this block forward into the sandbox so the next (higher) block sees
      # the coins it creates / spends — replays ConnectBlock's UTXO mutation in
      # the overlay only (never the live DB), so input lookups stay correct as we
      # climb back to the tip.
      for txi in 0 ..< blk.txs.len:
        let tx = blk.txs[txi]
        let isCoinbaseTx = (txi == 0)
        if not isCoinbaseTx:
          for inp in tx.inputs:
            overlay[inp.prevOut] = none(UtxoEntry)  # spend
        let txid = tx.txid()
        for voutIdx in 0 ..< tx.outputs.len:
          if isUnspendable(tx.outputs[voutIdx].scriptPubKey):
            continue
          let op = OutPoint(txid: txid, vout: uint32(voutIdx))
          overlay[op] = some(UtxoEntry(
            output: tx.outputs[voutIdx],
            height: height,
            isCoinbase: isCoinbaseTx))

  info "verifychain: no inconsistencies", lastN = checkDepth, level = checkLevel
  %true

proc handleMethod*(rpc: RpcServer, methodName: string, params: JsonNode): JsonNode =
  case methodName
  # Blockchain
  of "getblockchaininfo":
    rpc.handleGetBlockchainInfo()
  of "getblockcount":
    rpc.handleGetBlockCount()
  of "getbestblockhash":
    rpc.handleGetBestBlockHash()
  of "getchainstates":
    rpc.handleGetChainStates()
  of "getsyncstate":
    rpc.handleGetSyncState()
  of "getblockhash":
    rpc.handleGetBlockHash(params)
  of "getblockheader":
    rpc.handleGetBlockHeader(params)
  of "getblock":
    rpc.handleGetBlock(params)
  of "getblockfrompeer":
    rpc.handleGetBlockFromPeer(params)
  of "getdifficulty":
    rpc.handleGetDifficulty()
  of "getchaintips":
    rpc.handleGetChainTips()
  of "pruneblockchain":
    rpc.handlePruneBlockchain(params)
  of "gettxout":
    rpc.handleGetTxOut(params)
  of "getdeploymentinfo":
    rpc.handleGetDeploymentInfo(params)
  of "getchaintxstats":
    rpc.handleGetChainTxStats(params)
  of "getblockstats":
    rpc.handleGetBlockStats(params)
  of "getindexinfo":
    rpc.handleGetIndexInfo(params)
  of "getblockfilter":
    rpc.handleGetBlockFilter(params)
  of "verifychain":
    rpc.handleVerifyChain(params)

  # Wait-family RPCs (waitfornewblock / waitforblock / waitforblockheight).
  # The blocking, event-driven path runs in asyncHandleRequest (the async
  # front door) for single requests. These sync entries exist so the methods
  # are recognised in a JSON-RPC BATCH (which the sync path serves) instead of
  # erroring "method not found": they validate the params with Core's exact
  # error codes (-8 / -1 / -3) and then return the current tip immediately
  # (non-blocking — a synchronous block here would freeze the whole RPC
  # thread's event loop, which is worse than not waiting inside a batch).
  of "waitfornewblock":
    discard parseWaitTimeoutMs(params, 0)
    if params.kind == JArray and params.len > 1 and params[1].kind != JNull:
      if params[1].kind != JString:
        raise newRpcError(RpcInvalidParameter,
          "current_tip must be hexadecimal string (not '" & $params[1] & "')")
      validateHashV(params[1].getStr(), "current_tip")
    let (h0, ht0) = rpc.currentTipDisplay()
    %*{"hash": h0, "height": ht0}
  of "waitforblock":
    if params.kind != JArray or params.len < 1 or params[0].kind == JNull:
      raise newRpcError(RpcInvalidParameter,
        "blockhash must be hexadecimal string (not 'null')")
    if params[0].kind != JString:
      raise newRpcError(RpcInvalidParameter,
        "blockhash must be hexadecimal string (not '" & $params[0] & "')")
    validateHashV(params[0].getStr(), "blockhash")
    discard parseWaitTimeoutMs(params, 1)
    let (h1, ht1) = rpc.currentTipDisplay()
    %*{"hash": h1, "height": ht1}
  of "waitforblockheight":
    discard parseWaitHeight(params, 0)
    discard parseWaitTimeoutMs(params, 1)
    let (h2, ht2) = rpc.currentTipDisplay()
    %*{"hash": h2, "height": ht2}

  # Chain management
  of "invalidateblock":
    rpc.handleInvalidateBlock(params)
  of "reconsiderblock":
    rpc.handleReconsiderBlock(params)
  of "preciousblock":
    rpc.handlePreciousBlock(params)

  # assumeUTXO / Snapshot
  of "dumptxoutset":
    rpc.handleDumpTxOutSet(params)
  of "loadtxoutset":
    rpc.handleLoadTxOutSet(params)
  of "gettxoutsetinfo":
    rpc.handleGetTxOutSetInfo(params)
  of "scantxoutset":
    rpc.handleScanTxOutSet(params)
  of "scanblocks":
    rpc.handleScanBlocks(params)
  of "scrubunspendable":
    rpc.handleScrubUnspendable(params)

  # Mempool
  of "getmempoolinfo":
    rpc.handleGetMempoolInfo()
  of "getrawmempool":
    rpc.handleGetRawMempool(params)
  of "getmempoolentry":
    rpc.handleGetMempoolEntry(params)
  of "getmempoolancestors":
    rpc.handleGetMempoolAncestors(params)
  of "getmempooldescendants":
    rpc.handleGetMempoolDescendants(params)
  of "dumpmempool":
    rpc.handleDumpMempool(params)
  of "loadmempool":
    rpc.handleLoadMempool(params)
  of "savemempool":
    # Bitcoin Core alias for dumpmempool. Keep parity.
    rpc.handleDumpMempool(params)
  of "getorphantxs":
    rpc.handleGetOrphanTxs(params)
  of "gettxspendingprevout":
    rpc.handleGetTxSpendingPrevout(params)

  # Raw transactions
  of "getrawtransaction":
    rpc.handleGetRawTransaction(params)
  of "createrawtransaction":
    rpc.handleCreateRawTransaction(params)
  of "decoderawtransaction":
    rpc.handleDecodeRawTransaction(params)
  of "combinerawtransaction":
    rpc.handleCombineRawTransaction(params)
  of "decodescript":
    rpc.handleDecodeScript(params)
  of "sendrawtransaction":
    rpc.handleSendRawTransaction(params)
  of "testmempoolaccept":
    rpc.handleTestMempoolAccept(params)
  of "submitpackage":
    rpc.handleSubmitPackage(params)

  # Network
  of "getnetworkinfo":
    rpc.handleGetNetworkInfo()
  of "ping":
    rpc.handlePing(params)
  of "setnetworkactive":
    rpc.handleSetNetworkActive(params)
  of "getpeerinfo":
    rpc.handleGetPeerInfo()
  of "getconnectioncount":
    rpc.handleGetConnectionCount()
  of "getnettotals":
    rpc.handleGetNetTotals()
  of "getnodeaddresses":
    rpc.handleGetNodeAddresses(params)
  of "addpeeraddress":
    rpc.handleAddPeerAddress(params)
  of "getaddrmaninfo":
    rpc.handleGetAddrmanInfo()
  of "addnode":
    rpc.handleAddNode(params)
  of "getaddednodeinfo":
    rpc.handleGetAddedNodeInfo(params)
  of "listbanned":
    rpc.handleListBanned()
  of "setban":
    rpc.handleSetBan(params)
  of "clearbanned":
    rpc.handleClearBanned()
  of "disconnectnode":
    rpc.handleDisconnectNode(params)

  # ZMQ
  of "getzmqnotifications":
    rpc.handleGetZmqNotifications()

  # Mining
  of "getmininginfo":
    rpc.handleGetMiningInfo()
  of "getblocktemplate":
    rpc.handleGetBlockTemplate(params)
  of "submitblock":
    rpc.handleSubmitBlock(params)
  of "submitheader":
    rpc.handleSubmitHeader(params)
  of "prioritisetransaction":
    rpc.handlePrioritiseTransaction(params)
  of "getprioritisedtransactions":
    rpc.handleGetPrioritisedTransactions(params)

  # Regtest mining
  of "generate":
    rpc.handleGenerate(params)
  of "generatetoaddress":
    rpc.handleGenerateToAddress(params)
  of "generatetodescriptor":
    rpc.handleGenerateToDescriptor(params)
  of "generateblock":
    rpc.handleGenerateBlock(params)

  # Fee estimation
  of "estimatesmartfee":
    rpc.handleEstimateSmartFee(params)
  of "estimaterawfee":
    rpc.handleEstimateRawFee(params)

  # Message signing
  of "signmessage":
    rpc.handleSignMessage(params)
  of "signmessagewithprivkey":
    rpc.handleSignMessageWithPrivkey(params)
  of "verifymessage":
    rpc.handleVerifyMessage(params)

  # Utility
  of "validateaddress":
    rpc.handleValidateAddress(params)

  # Wallet management
  of "createwallet":
    rpc.handleCreateWallet(params)
  of "loadwallet":
    rpc.handleLoadWallet(params)
  of "unloadwallet":
    rpc.handleUnloadWallet(params)
  of "listwallets":
    rpc.handleListWallets(params)
  of "listwalletdir":
    rpc.handleListWalletDir(params)

  # Wallet
  of "getnewaddress":
    rpc.handleGetNewAddress(params)
  of "getaddressinfo":
    rpc.handleGetAddressInfo(params)
  of "sethdseed":
    rpc.handleSetHdSeed(params)
  of "getrawchangeaddress":
    rpc.handleGetRawChangeAddress(params)
  of "getbalance":
    rpc.handleGetBalance(params)
  of "listunspent":
    rpc.handleListUnspent(params)
  of "getwalletinfo":
    rpc.handleGetWalletInfo(params)
  of "sendtoaddress":
    rpc.handleSendToAddress(params)
  of "listtransactions":
    rpc.handleListTransactions(params)
  of "gettransaction":
    rpc.handleGetTransaction(params)

  # Wallet import / rescan
  of "rescanblockchain":
    rpc.handleRescanBlockchain(params)
  of "importprivkey":
    rpc.handleImportPrivKey(params)
  of "dumpprivkey":
    rpc.handleDumpPrivKey(params)

  # Wallet encryption
  of "encryptwallet":
    rpc.handleEncryptWallet(params)
  of "walletpassphrase":
    rpc.handleWalletPassphrase(params)
  of "walletlock":
    rpc.handleWalletLock(params)
  of "walletpassphrasechange":
    rpc.handleWalletPassphraseChange(params)

  # Address labels
  of "setlabel":
    rpc.handleSetLabel(params)
  of "getaddressesbylabel":
    rpc.handleGetAddressesByLabel(params)
  of "listlabels":
    rpc.handleListLabels(params)

  # Multisig
  of "createmultisig":
    rpc.handleCreateMultisig(params)

  # Descriptors
  of "getdescriptorinfo":
    rpc.handleGetDescriptorInfo(params)
  of "deriveaddresses":
    rpc.handleDeriveAddresses(params)
  of "importdescriptors":
    rpc.handleImportDescriptors(params)
  of "listdescriptors":
    rpc.handleListDescriptors(params)

  # PSBT
  of "createpsbt":
    rpc.handleCreatePsbt(params)
  of "decodepsbt":
    rpc.handleDecodePsbt(params)
  of "combinepsbt":
    rpc.handleCombinePsbt(params)
  of "converttopsbt":
    rpc.handleConvertToPsbt(params)
  of "joinpsbts":
    rpc.handleJoinPsbts(params)
  of "finalizepsbt":
    rpc.handleFinalizePsbt(params)
  of "analyzepsbt":
    rpc.handleAnalyzePsbt(params)
  of "walletcreatefundedpsbt":
    rpc.handleWalletCreateFundedPsbt(params)
  of "walletprocesspsbt":
    rpc.handleWalletProcessPsbt(params)
  of "fundrawtransaction":
    rpc.handleFundRawTransaction(params)

  # Fee bumping (BIP-125) — FIX-61 W118 G22 closure
  of "bumpfee":
    rpc.handleBumpFee(params)
  of "psbtbumpfee":
    rpc.handlePsbtBumpFee(params)

  # PayJoin (BIP-78) — FIX-66 W119 G26+G27 closure
  of "getpayjoinrequest", "newpayjoinrequest":
    rpc.handleGetPayJoinRequest(params)
  of "sendpayjoinrequest", "startpayjoin":
    rpc.handleSendPayJoinRequest(params)

  # Wallet signing
  of "signrawtransactionwithwallet":
    rpc.handleSignRawTransactionWithWallet(params)

  # Control
  of "stop":
    # Return success - actual shutdown handled by caller
    %"nimrod server stopping"
  of "uptime":
    rpc.handleUptime()
  of "getmemoryinfo":
    rpc.handleGetMemoryInfo(params)
  of "logging":
    rpc.handleLogging(params)
  of "help":
    rpc.handleHelp(params)

  # Wave-47b P2 RPCs
  of "getnetworkhashps":
    rpc.handleGetNetworkHashPS(params)
  of "gettxoutproof":
    rpc.handleGetTxOutProof(params)
  of "verifytxoutproof":
    rpc.handleVerifyTxOutProof(params)
  of "getrpcinfo":
    rpc.handleGetRPCInfo()

  else:
    raise newRpcError(RpcMethodNotFound, "method not found: " & methodName)

proc namedArgPositions(methodName: string): seq[string] =
  ## Positional argument-name tables for object-form ("named") params.
  ## Bitcoin Core accepts named params for EVERY RPC via a table-driven
  ## transform (src/rpc/server.cpp:368-470 transformNamedArguments, invoked
  ## from ExecuteCommand at 502-511). nimrod's handlers are positional-only,
  ## so this covers the wallet/descriptor surface where named-args use is
  ## common (createwallet from descriptor-wallet tooling being the observed
  ## case). An empty seq means "method known, takes no arguments"; methods
  ## not listed raise -32602 (instead of the historic std/json
  ## AssertionDefect that the transport layer misreported as -32700).
  case methodName
  of "createwallet":
    @["wallet_name", "disable_private_keys", "blank", "passphrase",
      "avoid_reuse", "descriptors", "load_on_startup", "external_signer"]
  of "loadwallet": @["filename", "load_on_startup"]
  of "unloadwallet": @["wallet_name", "load_on_startup"]
  of "importdescriptors": @["requests"]
  of "listdescriptors": @["private"]
  of "getaddressinfo": @["address"]
  of "getwalletinfo", "listwallets", "listwalletdir": @[]
  of "getnewaddress": @["label", "address_type"]
  of "getbalance": @["dummy", "minconf", "include_watchonly", "avoid_reuse"]
  of "listunspent":
    @["minconf", "maxconf", "addresses", "include_unsafe", "query_options"]
  of "sendtoaddress":
    @["address", "amount", "comment", "comment_to", "subtractfeefromamount",
      "replaceable", "conf_target", "estimate_mode"]
  of "importprivkey": @["privkey", "label", "rescan"]
  of "rescanblockchain": @["start_height", "stop_height"]
  of "getdescriptorinfo": @["descriptor"]
  of "deriveaddresses": @["descriptor", "range"]
  of "getmemoryinfo": @["mode"]
  of "logging": @["include", "exclude"]
  else:
    raise newRpcError(RpcInvalidParams,
      "Named parameters are not supported for method " & methodName &
      "; pass params as a positional array")

proc transformNamedParams(methodName: string, params: JsonNode): JsonNode =
  ## Map a JObject params node onto the positional array the handlers expect.
  ## Mirrors Core transformNamedArguments: unspecified interior positions are
  ## filled with JSON null (handlers already treat JNull as "absent"), and an
  ## unknown name is RPC_INVALID_PARAMETER (-8, Core rpc/server.cpp:465-467).
  ## Duplicate keys cannot survive std/json parsing, so Core's duplicate check
  ## is structurally unreachable here.
  let argNames = namedArgPositions(methodName)
  var slots: seq[JsonNode] = @[]
  for key, val in params:
    let idx = argNames.find(key)
    if idx < 0:
      raise newRpcError(RpcInvalidParameter, "Unknown named parameter " & key)
    while slots.len <= idx:
      slots.add(newJNull())
    slots[idx] = val
  result = newJArray()
  for s in slots:
    result.add(s)

proc makeErrorResponse(id: JsonNode, code: int, message: string): string =
  $ %*{
    "jsonrpc": "2.0",
    "id": id,
    "result": newJNull(),
    "error": %*{
      "code": code,
      "message": message
    }
  }

proc handleSingleRequest(rpc: RpcServer, reqJson: JsonNode): JsonNode =
  ## Handle a single JSON-RPC request object
  ## Returns the JSON response object (not stringified)
  var requestId = newJNull()

  try:
    # Extract id first so error responses include it
    if reqJson.hasKey("id"):
      requestId = reqJson["id"]

    # Validate request is an object
    if reqJson.kind != JObject:
      return %*{
        "jsonrpc": "2.0",
        "id": requestId,
        "result": newJNull(),
        "error": %*{"code": RpcInvalidRequest, "message": "Invalid Request object"}
      }

    # Extract method
    if not reqJson.hasKey("method"):
      return %*{
        "jsonrpc": "2.0",
        "id": requestId,
        "result": newJNull(),
        "error": %*{"code": RpcInvalidRequest, "message": "Missing method"}
      }

    let methodName = reqJson["method"].getStr()
    if methodName == "":
      return %*{
        "jsonrpc": "2.0",
        "id": requestId,
        "result": newJNull(),
        "error": %*{"code": RpcInvalidRequest, "message": "Method must be a string"}
      }

    # Extract params (default to empty array)
    var params = newJArray()
    if reqJson.hasKey("params"):
      params = reqJson["params"]

    # Object-form ("named") params: transform to positional before dispatch.
    # Core does this for every RPC (rpc/server.cpp:507-508); we cover the
    # wallet/descriptor surface and return a clean -32602 elsewhere. This
    # also closes the old failure mode where params[0] on a JObject raised
    # an AssertionDefect that the transport layer reported as -32700.
    if params.kind == JObject:
      params = transformNamedParams(methodName, params)

    # Execute the method
    let methodResult = rpc.handleMethod(methodName, params)
    return %*{
      "jsonrpc": "2.0",
      "id": requestId,
      "result": methodResult,
      "error": newJNull()
    }
  except RpcError as e:
    return %*{
      "jsonrpc": "2.0",
      "id": requestId,
      "result": newJNull(),
      "error": %*{"code": e.code, "message": e.msg}
    }
  except CatchableError as e:
    return %*{
      "jsonrpc": "2.0",
      "id": requestId,
      "result": newJNull(),
      "error": %*{"code": RpcInternalError, "message": "internal error: " & e.msg}
    }

proc decodeUrlPathSegment(s: string): string =
  ## Minimal percent-decoding for a URL path segment (wallet names). Decodes
  ## %XX escapes; leaves everything else as-is.
  result = ""
  var i = 0
  while i < s.len:
    if s[i] == '%' and i + 2 < s.len:
      try:
        result.add(char(parseHexInt(s[i+1 .. i+2])))
        i += 3
        continue
      except CatchableError:
        discard
    result.add(s[i])
    inc i

proc handleRequest(rpc: RpcServer, body: string, reqPath: string = ""): string =
  ## Handle a JSON-RPC request (single or batch)
  ## Reference: Bitcoin Core httprpc.cpp HTTPReq_JSONRPC
  ##
  ## reqPath is the HTTP request path. The /wallet/<name> endpoint selects which
  ## loaded wallet wallet RPCs operate on (Core's multi-wallet convention); we
  ## record it in currentWalletName, consumed by getTargetWallet. A bare "/"
  ## leaves it empty (single-wallet / default resolution).
  block setWallet:
    var p = reqPath
    # Strip a query string if present.
    let q = p.find('?')
    if q >= 0:
      p = p[0 ..< q]
    if p.startsWith("/wallet/"):
      rpc.currentWalletName = decodeUrlPathSegment(p["/wallet/".len .. ^1])
    else:
      rpc.currentWalletName = ""

  var parsedJson: JsonNode

  # Parse the JSON body
  try:
    parsedJson = parseJson(body)
  except json.JsonParsingError as e:
    return makeErrorResponse(newJNull(), RpcParseError, "Parse error: " & e.msg)
  except CatchableError as e:
    return makeErrorResponse(newJNull(), RpcParseError, "Parse error: " & e.msg)

  # Handle batch requests (JSON array)
  if parsedJson.kind == JArray:
    # Empty batch is an error per JSON-RPC 2.0 spec, but Bitcoin Core
    # returns empty array for backwards compatibility
    if parsedJson.len == 0:
      return makeErrorResponse(newJNull(), RpcInvalidRequest, "Empty batch array")

    # Limit batch size to prevent DoS
    if parsedJson.len > MaxBatchSize:
      return makeErrorResponse(newJNull(), RpcInvalidRequest,
        "Batch size " & $parsedJson.len & " exceeds limit of " & $MaxBatchSize)

    # Execute each request and collect responses
    var responses = newJArray()
    for reqJson in parsedJson:
      let response = rpc.handleSingleRequest(reqJson)
      responses.add(response)

    return $responses

  # Handle single request (JSON object)
  if parsedJson.kind == JObject:
    let response = rpc.handleSingleRequest(parsedJson)
    return $response

  # Neither object nor array - invalid
  return makeErrorResponse(newJNull(), RpcParseError, "Top-level object parse error")

proc isWaitMethod(m: string): bool =
  m == "waitfornewblock" or m == "waitforblock" or m == "waitforblockheight"

proc handleRequestSafe(rpc: RpcServer, body: string, reqPath: string): string {.gcsafe.} =
  ## `handleRequest` wrapper that catches the full `Exception` surface (the
  ## sync path can raise non-Catchable Defects via deep JSON/codec calls) so it
  ## can be called from the async front door, whose machinery only permits a
  ## restricted raises set. Mirrors the processClient catch ladder. The original
  ## processClient call site wrapped handleRequest in `{.gcsafe.}` for the same
  ## reason; preserve that.
  {.gcsafe.}:
    try:
      result = rpc.handleRequest(body, reqPath)
    except CatchableError:
      result = makeErrorResponse(newJNull(), RpcInternalError, "internal error")
    except Exception:
      result = makeErrorResponse(newJNull(), RpcParseError, "parse error")

proc asyncHandleRequest(rpc: RpcServer, body: string,
                        reqPath: string = ""): Future[string] {.async.} =
  ## Async front door for the request path. The three wait-family RPCs must
  ## AWAIT a tip change (yielding the RPC thread's event loop so concurrent
  ## RPCs — e.g. a second connection's generate/submitblock — keep running),
  ## which the synchronous `handleRequest` dispatch cannot do. This intercepts
  ## a single-object request to one of those three methods and runs the async
  ## handler with a proper JSON-RPC envelope; EVERYTHING ELSE (every other
  ## method, all batch requests) delegates unchanged to the synchronous
  ## `handleRequest`, so existing behaviour is byte-for-byte preserved.
  var parsed: JsonNode
  try:
    parsed = parseJson(body)
  except CatchableError:
    # Let the sync path produce the exact parse-error envelope.
    return rpc.handleRequestSafe(body, reqPath)

  # Only single-object requests to a wait method take the async path.
  if parsed.kind != JObject or not parsed.hasKey("method") or
     parsed["method"].kind != JString or
     not isWaitMethod(parsed["method"].getStr()):
    return rpc.handleRequestSafe(body, reqPath)

  # Set the per-request wallet context exactly as the sync path does (harmless
  # for these non-wallet RPCs, but keeps the field consistent).
  block setWallet:
    var p = reqPath
    let q = p.find('?')
    if q >= 0: p = p[0 ..< q]
    if p.startsWith("/wallet/"):
      rpc.currentWalletName = decodeUrlPathSegment(p["/wallet/".len .. ^1])
    else:
      rpc.currentWalletName = ""

  let methodName = parsed["method"].getStr()
  var requestId: JsonNode = newJNull()
  if parsed.hasKey("id"):
    requestId = parsed["id"]

  var params = newJArray()
  if parsed.hasKey("params"):
    params = parsed["params"]
  if params.kind == JObject:
    try:
      params = transformNamedParams(methodName, params)
    except RpcError as e:
      return makeErrorResponse(requestId, e.code, e.msg)
    except CatchableError as e:
      return makeErrorResponse(requestId, RpcInvalidParams, e.msg)

  try:
    let res =
      case methodName
      of "waitfornewblock":    await rpc.rpcWaitForNewBlock(params)
      of "waitforblock":       await rpc.rpcWaitForBlock(params)
      of "waitforblockheight": await rpc.rpcWaitForBlockHeight(params)
      else:                    newJNull()  # unreachable (isWaitMethod gate)
    return $ %*{
      "jsonrpc": "2.0",
      "id": requestId,
      "result": res,
      "error": newJNull()
    }
  except RpcError as e:
    return makeErrorResponse(requestId, e.code, e.msg)
  except CatchableError as e:
    return makeErrorResponse(requestId, RpcInternalError, "internal error: " & e.msg)

proc checkAuth(rpc: RpcServer, authHeader: string): bool =
  ## Verify HTTP Basic auth credentials.
  ## Accepts either --rpcuser/--rpcpassword credentials or the auto-generated
  ## __cookie__:<hex> cookie credential (matching Bitcoin Core behaviour).
  let hasUserPass = rpc.authUser != "" and rpc.authPass != ""
  let hasCookie   = rpc.cookiePassword != ""

  if not hasUserPass and not hasCookie:
    return true  # No auth configured — open access

  if not authHeader.startsWith("Basic "):
    return false

  try:
    let decoded = decode(authHeader[6 .. ^1])
    # split on first ':' only — passwords may contain colons
    let colonIdx = decoded.find(':')
    if colonIdx < 0:
      return false
    let user = decoded[0 ..< colonIdx]
    let pass = decoded[colonIdx + 1 .. ^1]

    # Cookie auth: username must be exactly "__cookie__"
    if user == "__cookie__" and hasCookie:
      return pass == rpc.cookiePassword

    # Regular user/password auth
    if hasUserPass:
      return user == rpc.authUser and pass == rpc.authPass

    return false
  except CatchableError:
    return false

proc processClient(rpc: RpcServer, transp: StreamTransport) {.async.} =
  ## Handle a single client connection with proper HTTP parsing
  var headers: Table[string, string]
  var contentLength = 0
  var inHeaders = true
  var authHeader = ""
  # Per-request URL path, captured from the HTTP request line. Used to route
  # wallet RPCs to the wallet named in /wallet/<name> (Bitcoin Core's
  # -rpcwallet / multi-wallet endpoint convention). "" means no specific wallet.
  var reqPath = ""

  while not transp.closed:
    try:
      if inHeaders:
        let line = await transp.readLine()

        if line.len == 0 and transp.atEof():
          # Connection closed by remote — stop processing
          break

        if line.len == 0:
          # End of headers
          inHeaders = false

          # Check auth
          if not rpc.checkAuth(authHeader):
            let response = "HTTP/1.1 401 Unauthorized\r\n" &
                          "WWW-Authenticate: Basic realm=\"nimrod\"\r\n" &
                          "Connection: close\r\n" &
                          "Content-Length: 0\r\n" &
                          "\r\n"
            discard await transp.write(response)
            break

          # Read body based on Content-Length
          if contentLength > 0:
            let bodyData = await transp.read(contentLength)
            let body = cast[string](bodyData)

            # Yield to the event loop before the synchronous chain-state read so
            # that other pending futures (peer I/O, sync loop heartbeats) are not
            # starved during heavy RPC calls like getblock or gettxoutsetinfo.
            await sleepAsync(0)

            # asyncHandleRequest awaits a tip change for the wait-family RPCs
            # (waitfornewblock / waitforblock / waitforblockheight), yielding
            # the event loop so concurrent RPCs keep running; every other
            # method delegates synchronously to handleRequest unchanged.
            var respResult: string
            try:
              respResult = await rpc.asyncHandleRequest(body, reqPath)
            except CatchableError:
              respResult = makeErrorResponse(newJNull(), RpcInternalError, "internal error")
            except Exception:
              respResult = makeErrorResponse(newJNull(), RpcParseError, "parse error")

            let httpResponse = "HTTP/1.1 200 OK\r\n" &
                              "Content-Type: application/json\r\n" &
                              "Connection: close\r\n" &
                              "Content-Length: " & $respResult.len & "\r\n" &
                              "\r\n" & respResult
            discard await transp.write(httpResponse)
            # Connection: close — finish after each request
            break

          # Reset for next request (keep-alive)
          inHeaders = true
          headers.clear()
          contentLength = 0
          authHeader = ""
          reqPath = ""

        elif line.startsWith("POST") or line.startsWith("GET"):
          # Request line: "<METHOD> <path> HTTP/1.x" — capture the path so the
          # /wallet/<name> endpoint can route wallet RPCs to a named wallet.
          let parts = line.split(' ')
          if parts.len >= 2:
            reqPath = parts[1]

        elif line.contains(":"):
          let colonIdx = line.find(':')
          let key = line[0 ..< colonIdx].strip().toLowerAscii()
          let value = line[colonIdx + 1 .. ^1].strip()

          headers[key] = value

          if key == "content-length":
            contentLength = parseInt(value)
          elif key == "authorization":
            authHeader = value

    except CatchableError:
      break

  await transp.closeWait()

proc start*(rpc: RpcServer) {.async.} =
  ## Start the RPC server (binds to localhost only)
  let ta = initTAddress("127.0.0.1", Port(rpc.port))
  let server = createStreamServer(ta, flags = {ReuseAddr})

  rpc.running = true
  info "RPC server started", port = rpc.port

  while rpc.running:
    try:
      let transp = await server.accept()
      asyncSpawn rpc.processClient(transp)
    except CatchableError as e:
      if rpc.running:
        error "RPC server error", error = e.msg

  server.close()

proc stop*(rpc: RpcServer) =
  rpc.running = false

# Convenience function for backward compatibility
proc startRpcServer*(rpc: RpcServer) {.async.} =
  await rpc.start()
