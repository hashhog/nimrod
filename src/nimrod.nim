## nimrod - Bitcoin full node in Nim
## Unified CLI with subcommands for node operation, RPC interaction, and wallet management

import std/[parseopt, os, strutils, json, posix, net, base64, sysrand, tables, monotimes, times, sets, options, algorithm]
import chronos
import chronicles

import ./primitives/[types, serialize]
import ./consensus/[params, validation]
import ./storage/[db, chainstate, snapshot, blockstore, pruner]
import ./storage/indexes/[blockfilterindex, gcs]
import ./network/[peer, peermanager, sync, messages]
import ./mempool/[mempool, persist, orphan]
import ./mining/fees
import ./rpc/server
import ./rpc/rpc_thread
import ./rpc/rest
import ./crypto/[secp256k1, hashing]
import ./util/ops

const NimrodVersion* = "0.1.0"

type
  Command* = enum
    cmdStart = "start"
    cmdStop = "stop"
    cmdGetInfo = "getinfo"
    cmdGetBlock = "getblock"
    cmdSendRawTx = "sendrawtransaction"
    cmdGetBalance = "getbalance"
    cmdSendTo = "sendtoaddress"
    cmdGetNewAddress = "getnewaddress"
    cmdHelp = "help"
    cmdVersion = "version"

  NimrodConfig* = object
    dataDir*: string
    network*: string
    rpcPort*: uint16
    p2pPort*: uint16
    logLevel*: string
    maxConnections*: int
    rpcEnabled*: bool
    rpcUser*: string
    rpcPassword*: string
    bindAddr*: string
    pruneTarget*: uint64  ## Prune target in MiB (0 = disabled, 1 = manual only)
    importBlocks*: string ## Path to blk*.dat directory, or "-" for framed stdin
    metricsPort*: uint16  ## Prometheus metrics port (0 = disabled)
    ibdFlushInterval*: int ## Disk flush interval during IBD (0 = use default 2000)
    numVerifyWorkers*: int ## Script verify thread count for parallel IBD (0 = auto = CPU count)
    # ---- Operational flags (Bitcoin Core parity) ----
    daemon*: bool         ## --daemon: detach via fork+setsid; suppresses console.
    pidFile*: string      ## --pid=<path>: PID file (default <datadir>/nimrod.pid)
    confFile*: string     ## --conf=<path>: explicit config file (overrides default
                          ## <datadir>/nimrod.conf)
    debugCategories*: string ## --debug=<cat,...>: chronicles topics to enable
    printToConsole*: bool ## --printtoconsole: keep stdout/stderr live even with
                          ## --daemon. Without this and with --daemon, logs go
                          ## to <datadir>/<network>/debug.log.
    logFile*: string      ## --debuglogfile=<path>: explicit log destination.
                          ## Empty == derive from datadir (or stdout if console).
    readyFd*: int         ## --ready-fd=<N>: write '\n' to FD N once startup
                          ## reaches the main loop. -1 = disabled.
    reindex*: bool        ## --reindex: wipe chainstate before start (HONEST
                          ## PROGRESS — does NOT re-scan blk*.dat; we drop
                          ## chainstate so the next start triggers fresh IBD).
    loadSnapshot*: string ## --load-snapshot=<path>: load a Bitcoin Core
                          ## byte-compatible UTXO snapshot before entering
                          ## the main loop (assumeUTXO fast-sync). Must
                          ## point to a fresh, network-matching snapshot.
    restEnabled*: bool    ## --rest: serve the read-only Bitcoin Core REST
                          ## surface (/rest/block, /rest/headers,
                          ## /rest/blockfilter, …). Default OFF — matches
                          ## Bitcoin Core's `-rest` flag (also default off).
    restPort*: uint16     ## --restport=N: TCP port for the REST listener
                          ## (default: rpcPort + 1000). REST is bound to its
                          ## own port — Core shares the JSON-RPC socket, but
                          ## nimrod's RPC runs on a dedicated thread (see
                          ## rpc_thread.nim) so REST gets its own listener.
    blockfilterindex*: bool ## --blockfilterindex: maintain the BIP-157
                            ## "basic" filter index. Mirrors Bitcoin Core's
                            ## `-blockfilterindex=basic`. Required for the
                            ## /rest/blockfilter[headers] endpoints to
                            ## return data; without it those endpoints
                            ## report "Index is not enabled for filtertype
                            ## basic" (HTTP 400) — same as Core.

  NodeState* = ref object
    config*: NimrodConfig
    params*: ConsensusParams
    chainState*: ChainState
    mempool*: Mempool
    peerManager*: PeerManager
    syncManager*: SyncManager
    feeEstimator*: FeeEstimator
    rpcServer*: RpcServer
    rpcThread*: RpcThreadHandle  ## Owns the lifetime of the RPC OS thread.
                                 ## MUST be held by NodeState — discarding the
                                 ## handle frees its `Thread[RpcServer]` core
                                 ## while the pthread is still reading from
                                 ## `addr(t)`, causing an unattributed SIGSEGV
                                 ## on regtest startup (and a flaky one on
                                 ## testnet/mainnet) because the new pthread
                                 ## races with the destructor that fires when
                                 ## the temporary handle is dropped.
    crypto*: CryptoEngine
    running*: bool
    recentlyRejected*: HashSet[TxId]  ## Recently-rejected tx filter, cleared on new block
    orphanPool*: OrphanPool           ## Tx orphan pool: holds txs whose
                                       ## parents we haven't seen yet, for
                                       ## ~20 min, capped at 100 entries
                                       ## globally and 25 per peer.  Mirrors
                                       ## bitcoin-core/src/node/txorphanage.
    blockFileManager*: BlockFileManager  ## Block-file metadata holder. Wired
                                          ## into the RPC server so
                                          ## getblockchaininfo and
                                          ## pruneblockchain answer correctly
                                          ## even when block bodies live in
                                          ## RocksDB (the production layout).
    pruner*: Pruner                       ## Production prune driver. Owns
                                          ## the auto-prune trigger and the
                                          ## RocksDB-backed delete loop.
                                          ## nil when --prune is not set.
    blockFilterIndex*: BlockFilterIndex   ## BIP-157 basic filter index.
                                          ## nil when --blockfilterindex is
                                          ## not set. Wired into RestServer
                                          ## so /rest/blockfilter[headers]
                                          ## can read it.
    restServer*: RestServer               ## Optional /rest/* HTTP server.
                                          ## nil when --rest is not set.
    restThread*: Thread[RestServer]       ## REST listener runs on its own
                                          ## OS thread — same rationale as
                                          ## the RPC thread (event-loop
                                          ## isolation from main-thread
                                          ## verifyScripts batches; see
                                          ## rpc_thread.nim).

# Global for signal handling
var globalNodeState*: NodeState = nil

proc defaultConfig*(): NimrodConfig =
  NimrodConfig(
    dataDir: getHomeDir() / ".nimrod",
    network: "mainnet",
    rpcPort: 8332,
    p2pPort: 8333,
    logLevel: "info",
    maxConnections: 125,
    rpcEnabled: true,
    rpcUser: "",
    rpcPassword: "",
    bindAddr: "0.0.0.0",
    pruneTarget: 0,  # Pruning disabled by default
    metricsPort: 9332,
    ibdFlushInterval: 0,  # 0 = use default (IbdBatchFlushInterval = 2000)
    numVerifyWorkers: 0,  # 0 = auto (CPU count via countProcessors())
    daemon: false,
    pidFile: "",          # derived from dataDir if empty
    confFile: "",         # default <dataDir>/nimrod.conf
    debugCategories: "",
    printToConsole: false,
    logFile: "",
    readyFd: -1,
    reindex: false,
    loadSnapshot: "",
    restEnabled: false,
    restPort: 0,            # 0 = derive from rpcPort (rpcPort + 1000)
    blockfilterindex: false
  )

proc loadConfigFile*(config: var NimrodConfig) =
  ## Load configuration from `config.confFile` if set, else from
  ## `<dataDir>/nimrod.conf`.  Silent no-op if the file doesn't exist
  ## (matches Bitcoin Core behaviour for `-conf=`).
  let confPath = if config.confFile.len > 0:
                   config.confFile
                 else:
                   config.dataDir / "nimrod.conf"
  if not fileExists(confPath):
    return

  for line in lines(confPath):
    let trimmed = line.strip()
    if trimmed.len == 0 or trimmed.startsWith("#"):
      continue

    let parts = trimmed.split("=", 1)
    if parts.len != 2:
      continue

    let key = parts[0].strip().toLowerAscii()
    let value = parts[1].strip()

    case key
    of "datadir":
      config.dataDir = value
    of "network":
      config.network = value
    of "rpcport":
      try: config.rpcPort = uint16(parseInt(value))
      except ValueError: discard
    of "port", "p2pport":
      try: config.p2pPort = uint16(parseInt(value))
      except ValueError: discard
    of "loglevel":
      config.logLevel = value
    of "maxconnections":
      try: config.maxConnections = parseInt(value)
      except ValueError: discard
    of "rpcuser":
      config.rpcUser = value
    of "rpcpassword":
      config.rpcPassword = value
    of "bind":
      config.bindAddr = value
    of "norpc":
      config.rpcEnabled = value.toLowerAscii() notin ["1", "true", "yes"]
    of "testnet":
      if value.toLowerAscii() in ["1", "true", "yes"]:
        config.network = "testnet3"
        if config.rpcPort == 8332: config.rpcPort = 18332
        if config.p2pPort == 8333: config.p2pPort = 18333
    of "regtest":
      if value.toLowerAscii() in ["1", "true", "yes"]:
        config.network = "regtest"
        if config.rpcPort == 8332: config.rpcPort = 18443
        if config.p2pPort == 8333: config.p2pPort = 18444
    of "prune":
      try:
        let pruneMiB = parseInt(value)
        if pruneMiB > 0:
          config.pruneTarget = uint64(pruneMiB)
      except ValueError: discard
    of "verifythreads", "verify-threads":
      try:
        let v = parseInt(value)
        if v >= 0 and v <= 256:
          config.numVerifyWorkers = v
      except ValueError: discard
    of "daemon":
      config.daemon = value.toLowerAscii() in ["1", "true", "yes"]
    of "pid":
      config.pidFile = value
    of "debug":
      # Allow comma-separated multi-category specs in the config file too.
      if config.debugCategories.len == 0:
        config.debugCategories = value
      else:
        config.debugCategories &= "," & value
    of "printtoconsole":
      config.printToConsole = value.toLowerAscii() in ["1", "true", "yes"]
    of "debuglogfile":
      config.logFile = value
    of "reindex":
      config.reindex = value.toLowerAscii() in ["1", "true", "yes"]
    of "rest":
      config.restEnabled = value.toLowerAscii() in ["1", "true", "yes"]
    of "restport":
      try: config.restPort = uint16(parseInt(value))
      except ValueError: discard
    of "blockfilterindex":
      # Core accepts `-blockfilterindex` (boolean) and
      # `-blockfilterindex=basic`. We treat any non-"0"/"false"/empty value
      # as enable-basic (the only filter type defined by BIP-158 today).
      let v = value.toLowerAscii()
      if v in ["", "1", "true", "yes", "basic"]:
        config.blockfilterindex = true
      elif v in ["0", "false", "no"]:
        config.blockfilterindex = false
    else:
      discard

proc showHelp() =
  echo """
nimrod v""" & NimrodVersion & """

A Bitcoin full node in Nim

Usage: nimrod [options] <command> [args]

Commands:
  start                  Start the node
  stop                   Stop a running node
  getinfo                Get node information
  getblock <hash>        Get block by hash
  sendrawtransaction <hex>  Broadcast raw transaction
  getbalance             Get wallet balance
  sendtoaddress <addr> <amount>  Send to address
  getnewaddress          Get new receiving address
  help                   Show this help
  version                Show version

Options:
  -d, --datadir=DIR      Data directory (default: ~/.nimrod)
  -n, --network=NET      Network: mainnet, testnet3, testnet4, regtest (default: mainnet)
  --testnet              Use testnet3
  --regtest              Use regtest
  --rpcport=PORT         RPC port (default: 8332)
  -p, --port=PORT        P2P port (default: 8333)
  -l, --loglevel=LEVEL   Log level: trace, debug, info, warn, error (default: info)
  --maxconnections=N     Maximum peer connections (default: 125)
  --rpcuser=USER         RPC username
  --rpcpassword=PASS     RPC password
  --bind=ADDR            P2P bind address (default: 0.0.0.0)
  --norpc                Disable RPC server
  --prune=SIZE_MB        Enable pruning. SIZE_MB=0 disables; SIZE_MB=1 enables
                         manual mode (only the pruneblockchain RPC prunes;
                         no auto-prune); SIZE_MB>=550 enables auto-prune to
                         the given byte budget (Bitcoin Core parity).
  --ibd-flush-interval=N Force memtables to disk every N blocks during IBD (default: 2000, max: 5000)
  --verify-threads=N     Script verify thread count for parallel IBD (default: 0 = auto/CPU count)

Operational:
  --daemon               Detach via fork+setsid (Bitcoin Core -daemon)
  --pid=PATH             PID file (default: <datadir>/nimrod.pid)
  --conf=PATH            Config file path (default: <datadir>/nimrod.conf)
  --debug=CAT[,CAT...]   Enable debug categories (net,p2p,sync,rpc,...; "all" enables all)
  --printtoconsole       Keep stdout/stderr live even with --daemon
  --debuglogfile=PATH    Log file path (default: <datadir>/<network>/debug.log under --daemon)
  --ready-fd=N           Write '\\n' to FD N when startup is complete (supervision)
  --reindex              Wipe chainstate before start (re-download from peers)
  --load-snapshot=PATH   Load a Bitcoin Core byte-compatible UTXO snapshot
                         (assumeUTXO) into chainstate before entering main loop
  --rest                 Enable the read-only REST HTTP server (default off,
                         matches Bitcoin Core -rest). Endpoints: /rest/block,
                         /rest/headers, /rest/blockhashbyheight, /rest/tx,
                         /rest/getutxos, /rest/mempool/info|contents,
                         /rest/blockfilter, /rest/blockfilterheaders.
  --restport=PORT        REST listener port (default: rpcport + 1000)
  --blockfilterindex     Maintain BIP-157 basic block-filter index. Required
                         for the /rest/blockfilter[headers] endpoints to
                         return data. Mirrors Bitcoin Core
                         -blockfilterindex=basic.

  -h, --help             Show this help
  -v, --version          Show version

Config file: <datadir>/nimrod.conf or path passed via --conf (key=value format)
SIGHUP: reopens the configured log file (rotation-friendly).
"""

proc parseArgs*(): tuple[cmd: Command, config: NimrodConfig, args: seq[string]] =
  ## Parse command line arguments
  ## Returns: command, config, and additional args
  result.config = defaultConfig()
  result.cmd = cmdStart  # Default command
  result.args = @[]

  var p = initOptParser()
  var cmdParsed = false

  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdShortOption, cmdLongOption:
      case p.key.toLowerAscii
      of "datadir", "d":
        result.config.dataDir = p.val
      of "network", "n":
        result.config.network = p.val
        case p.val.toLowerAscii
        of "testnet", "testnet3":
          result.config.network = "testnet3"
          if result.config.rpcPort == 8332: result.config.rpcPort = 18332
          if result.config.p2pPort == 8333: result.config.p2pPort = 18333
        of "testnet4":
          result.config.network = "testnet4"
          if result.config.rpcPort == 8332: result.config.rpcPort = 48332
          if result.config.p2pPort == 8333: result.config.p2pPort = 48333
        of "regtest":
          result.config.network = "regtest"
          if result.config.rpcPort == 8332: result.config.rpcPort = 18443
          if result.config.p2pPort == 8333: result.config.p2pPort = 18444
        else: discard
      of "rpcport":
        try: result.config.rpcPort = uint16(parseInt(p.val))
        except ValueError:
          echo "Invalid rpc port: " & p.val
          quit(1)
      of "port", "p":
        try: result.config.p2pPort = uint16(parseInt(p.val))
        except ValueError:
          echo "Invalid p2p port: " & p.val
          quit(1)
      of "loglevel", "l":
        result.config.logLevel = p.val
      of "maxconnections":
        try: result.config.maxConnections = parseInt(p.val)
        except ValueError:
          echo "Invalid maxconnections: " & p.val
          quit(1)
      of "rpcuser":
        result.config.rpcUser = p.val
      of "rpcpassword":
        result.config.rpcPassword = p.val
      of "bind":
        result.config.bindAddr = p.val
      of "norpc":
        result.config.rpcEnabled = false
      of "metricsport":
        try: result.config.metricsPort = uint16(parseInt(p.val))
        except ValueError:
          echo "Invalid metrics port: " & p.val
          quit(1)
      of "testnet":
        result.config.network = "testnet3"
        if result.config.rpcPort == 8332: result.config.rpcPort = 18332
        if result.config.p2pPort == 8333: result.config.p2pPort = 18333
      of "regtest":
        result.config.network = "regtest"
        if result.config.rpcPort == 8332: result.config.rpcPort = 18443
        if result.config.p2pPort == 8333: result.config.p2pPort = 18444
      of "prune":
        try:
          let pruneMiB = parseInt(p.val)
          if pruneMiB < 0:
            echo "Invalid prune value: must be non-negative"
            quit(1)
          # 0 = disabled; 1 = manual-only (Bitcoin Core sentinel); >= 550 =
          # automatic prune. 2..549 is rejected exactly the way Core does
          # (the manual sentinel is the only sub-floor value accepted).
          elif pruneMiB > 1 and pruneMiB < 550:
            echo "Prune configured below the minimum of 550 MiB " &
                 "(use --prune=1 for manual-only mode, or --prune=N with " &
                 "N >= 550 for auto-prune)"
            quit(1)
          result.config.pruneTarget = uint64(pruneMiB)
        except ValueError:
          echo "Invalid prune value: " & p.val
          quit(1)
      of "import-blocks", "importblocks":
        result.config.importBlocks = p.val
      of "ibd-flush-interval":
        try:
          let v = parseInt(p.val)
          if v < 0 or v > 5000:
            echo "ibd-flush-interval must be 0-5000 (0 = default 2000)"
            quit(1)
          result.config.ibdFlushInterval = v
        except ValueError:
          echo "Invalid ibd-flush-interval: " & p.val
          quit(1)
      of "verify-threads":
        try:
          let v = parseInt(p.val)
          if v < 0 or v > 256:
            echo "verify-threads must be 0-256 (0 = auto/CPU count)"
            quit(1)
          result.config.numVerifyWorkers = v
        except ValueError:
          echo "Invalid verify-threads: " & p.val
          quit(1)
      of "daemon":
        # Accept --daemon and --daemon=0/1.
        if p.val.len == 0:
          result.config.daemon = true
        else:
          result.config.daemon = p.val.toLowerAscii() in ["1", "true", "yes"]
      of "pid":
        result.config.pidFile = p.val
      of "conf":
        result.config.confFile = p.val
      of "debug":
        if result.config.debugCategories.len == 0:
          result.config.debugCategories = p.val
        else:
          result.config.debugCategories &= "," & p.val
      of "printtoconsole":
        if p.val.len == 0:
          result.config.printToConsole = true
        else:
          result.config.printToConsole = p.val.toLowerAscii() in ["1", "true", "yes"]
      of "debuglogfile":
        result.config.logFile = p.val
      of "ready-fd", "readyfd":
        try:
          let fd = parseInt(p.val)
          if fd < 0:
            echo "ready-fd must be a non-negative file descriptor"
            quit(1)
          result.config.readyFd = fd
        except ValueError:
          echo "Invalid ready-fd: " & p.val
          quit(1)
      of "reindex":
        if p.val.len == 0:
          result.config.reindex = true
        else:
          result.config.reindex = p.val.toLowerAscii() in ["1", "true", "yes"]
      of "load-snapshot", "loadsnapshot":
        if p.val.len == 0:
          echo "Invalid --load-snapshot: missing path"
          quit(1)
        result.config.loadSnapshot = p.val
      of "rest":
        # Accept `--rest` and `--rest=0/1`.
        if p.val.len == 0:
          result.config.restEnabled = true
        else:
          result.config.restEnabled = p.val.toLowerAscii() in ["1", "true", "yes"]
      of "restport", "rest-port":
        try: result.config.restPort = uint16(parseInt(p.val))
        except ValueError:
          echo "Invalid rest port: " & p.val
          quit(1)
      of "blockfilterindex":
        # Bitcoin Core accepts `-blockfilterindex` (boolean) and
        # `-blockfilterindex=basic`. Treat any non-"0"/"false"/empty value
        # as enable-basic (only filter type BIP-158 defines today).
        let v = p.val.toLowerAscii()
        if v.len == 0 or v in ["1", "true", "yes", "basic"]:
          result.config.blockfilterindex = true
        elif v in ["0", "false", "no"]:
          result.config.blockfilterindex = false
        else:
          echo "Invalid --blockfilterindex value: " & p.val &
               " (use 1 / 0 / basic)"
          quit(1)
      of "help", "h":
        showHelp()
        quit(0)
      of "version", "v":
        echo "nimrod v" & NimrodVersion
        quit(0)
      else:
        echo "Unknown option: " & p.key
        quit(1)
    of cmdArgument:
      if not cmdParsed:
        # First positional arg is the command
        case p.key.toLowerAscii
        of "start": result.cmd = cmdStart
        of "stop": result.cmd = cmdStop
        of "getinfo": result.cmd = cmdGetInfo
        of "getblock": result.cmd = cmdGetBlock
        of "sendrawtransaction": result.cmd = cmdSendRawTx
        of "getbalance": result.cmd = cmdGetBalance
        of "sendtoaddress": result.cmd = cmdSendTo
        of "getnewaddress": result.cmd = cmdGetNewAddress
        of "help":
          showHelp()
          quit(0)
        of "version":
          echo "nimrod v" & NimrodVersion
          quit(0)
        else:
          echo "Unknown command: " & p.key
          echo "Run 'nimrod help' for usage information"
          quit(1)
        cmdParsed = true
      else:
        # Additional args for the command
        result.args.add(p.key)

  # Load config file after parsing CLI (CLI overrides config file)
  var fileConfig = result.config
  loadConfigFile(fileConfig)

  # Merge: CLI takes precedence
  # Only use file values if CLI didn't explicitly set them
  # (This is simplified - a proper impl would track which were set)

proc getConsensusParams(config: NimrodConfig): ConsensusParams =
  case config.network.toLowerAscii
  of "mainnet", "main": mainnetParams()
  of "testnet", "testnet3", "test": testnet3Params()
  of "testnet4": testnet4Params()
  of "regtest": regtestParams()
  else:
    echo "Unknown network: " & config.network
    quit(1)

proc findLocatorFork(state: NodeState,
                     locatorHashes: seq[array[32, byte]]): int32 =
  ## Find the height of the latest block from `locatorHashes` that is in our
  ## active chain. Mirrors Bitcoin Core's Chainstate::FindForkInGlobalIndex
  ## (validation.cpp:120) -- the locator is sorted descending by height, so
  ## return as soon as we find one we know about. Returns 0 (genesis) if none
  ## of the locator hashes are in our chain. Returns -1 only if our chain is
  ## empty (no genesis loaded).
  if state.chainState.bestHeight < 0:
    return -1
  for h in locatorHashes:
    let bh = BlockHash(h)
    # Prefer the in-memory header chain (covers headers ahead of the block tip)
    if state.syncManager != nil:
      let heightOpt = state.syncManager.headerChain.getHeight(bh)
      if heightOpt.isSome:
        # Confirm the hash is still on our active header chain at that height.
        let onChainOpt = state.syncManager.headerChain.getHashByHeight(heightOpt.get())
        if onChainOpt.isSome and onChainOpt.get() == bh:
          return heightOpt.get()
    # Fall back to the persisted block index (for hashes pruned from memory).
    let idxOpt = state.chainState.db.getBlockIndex(bh)
    if idxOpt.isSome:
      let idx = idxOpt.get()
      let canonOpt = state.chainState.db.getBlockHashByHeight(idx.height)
      if canonOpt.isSome and canonOpt.get() == bh:
        return idx.height
  # No common ancestor found -- start from genesis.
  return 0

proc activeChainHashAtHeight(state: NodeState, height: int32): Option[BlockHash] =
  ## Return the active-chain block hash at the given height, preferring the
  ## in-memory header chain (which is consistent during IBD before flush).
  if height < 0:
    return none(BlockHash)
  if state.syncManager != nil:
    let h = state.syncManager.headerChain.getHashByHeight(height)
    if h.isSome:
      return h
  state.chainState.getBlockHashByHeight(height)

proc activeChainHeaderAtHeight(state: NodeState, height: int32): Option[BlockHeader] =
  ## Active-chain header lookup. Header-chain first, then disk-backed block.
  if height < 0:
    return none(BlockHeader)
  if state.syncManager != nil:
    let h = state.syncManager.headerChain.getHeaderByHeight(height)
    if h.isSome:
      return h
  let hashOpt = state.chainState.getBlockHashByHeight(height)
  if hashOpt.isSome:
    let blkOpt = state.chainState.db.getBlock(hashOpt.get())
    if blkOpt.isSome:
      return some(blkOpt.get().header)
  none(BlockHeader)

proc handleMessage(state: NodeState, peer: Peer, msg: P2PMessage) {.async.} =
  ## Handle incoming P2P messages
  case msg.kind
  of mkHeaders:
    await state.syncManager.handleHeaders(peer, msg.headers)

  of mkBlock:
    var blockAccepted = false
    try:
      blockAccepted = state.syncManager.processBlock(msg.blk)
    except Defect as e:
      # Log but don't crash — the block will be retried
      let ht = state.syncManager.chainTipHeight
      echo "DEFECT in processBlock (chainTip=", ht, "): ", e.msg
      when compileOption("stackTrace"):
        echo getStackTrace(e)
    if blockAccepted:
      # Remove confirmed transactions from mempool
      {.gcsafe.}:
        state.mempool.removeForBlock(msg.blk)
        # Drop orphans that were confirmed (or invalidated by double-spend)
        # in the new block.  Mirrors EraseForBlock in Core's txorphanage.
        if state.orphanPool != nil:
          discard state.orphanPool.removeForBlock(msg.blk)
      # Clear recently-rejected filter -- rejection reasons may no longer apply
      state.recentlyRejected.clear()

  of mkTx:
    var accepted = false
    var missingInputs = false
    let txid = msg.tx.txid()
    let orphanPeer: OrphanPeerId = (peer.address, peer.port)
    {.gcsafe.}:
      try:
        let txResult = state.mempool.acceptTransaction(msg.tx, state.crypto)
        accepted = txResult.isOk
        if not accepted:
          # acceptTransaction returns "input not found: ..." when at least
          # one input has no UTXO and no mempool parent.  Treat that as a
          # missing-parent (orphan) signal — every other rejection reason
          # is a hard fail (consensus, policy, RBF, ...) and the tx should
          # NOT enter the orphan pool.
          missingInputs = txResult.error.startsWith("input not found")
      except CatchableError:
        discard
      except Exception:
        discard
    if accepted:
      # Relay to peers
      asyncSpawn state.peerManager.broadcastTx(msg.tx)
      # Re-feed any orphans that were waiting on this tx as a parent.
      # Each child that resolves can in turn unblock its own children, so
      # we loop on a worklist until it drains.  Resolution failures are
      # recorded in recentlyRejected exactly like top-level failures.
      if state.orphanPool != nil:
        var work = @[txid]
        var iterations = 0
        while work.len > 0 and iterations < 64:
          inc iterations
          let parent = work.pop()
          let pending = state.orphanPool.takeChildrenOf(parent)
          for child in pending:
            var childOk = false
            {.gcsafe.}:
              try:
                let r = state.mempool.acceptTransaction(child.tx, state.crypto)
                childOk = r.isOk
              except CatchableError:
                discard
              except Exception:
                discard
            if childOk:
              asyncSpawn state.peerManager.broadcastTx(child.tx)
              work.add(child.txid)
            else:
              if state.recentlyRejected.len < 50_000:
                state.recentlyRejected.incl(child.txid)
    elif missingInputs:
      # Hold the orphan briefly in case the parent arrives.  Capped pool
      # mirrors Core (100 txs / 100KB / peer cap).  Note we do NOT add to
      # recentlyRejected here — that would block re-requesting from a
      # subsequent peer once we see the parent.
      if state.orphanPool != nil:
        discard state.orphanPool.addOrphan(msg.tx, orphanPeer)
    else:
      # Track rejection to avoid re-requesting
      if state.recentlyRejected.len < 50_000:
        state.recentlyRejected.incl(txid)

  of mkInv:
    # Request blocks we don't have
    var blockInvs: seq[InvVector]
    var txInvs: seq[InvVector]
    for item in msg.invItems:
      if item.invType == invBlock or item.invType == invWitnessBlock:
        # Request as witness block for segwit support
        blockInvs.add(InvVector(invType: invWitnessBlock, hash: item.hash))
      elif item.invType == invTx or item.invType == invWitnessTx:
        # Request unknown transactions
        let txid = TxId(item.hash)
        if not state.mempool.contains(txid) and txid notin state.recentlyRejected:
          txInvs.add(InvVector(invType: invWitnessTx, hash: item.hash))
    if blockInvs.len > 0:
      asyncSpawn spawnSafe(peer.sendGetData(blockInvs))
    if txInvs.len > 0:
      asyncSpawn spawnSafe(peer.sendGetData(txInvs))

  of mkGetData:
    # Handle data requests - serve blocks and transactions to peers.
    # Reference: bitcoin-core/src/net_processing.cpp ProcessGetData
    # (msg_type == NetMsgType::GETDATA, line 4128). Items we cannot satisfy
    # are aggregated into a single NOTFOUND so the peer can move on instead
    # of timing out.
    #
    # BIP-159 peer-served-blocks gate: when prune mode is on, refuse to
    # serve blocks below tip - MIN_BLOCKS_TO_KEEP (288).  Mirrors Core's
    # net_processing.cpp short-circuit; emits notfound rather than reading
    # a possibly-deleted block file.
    const MinBlocksToKeep: int32 = 288
    let pruneActive = pruneModeAdvertiseEnabled()
    var pruneHorizon: int32 = -1
    if pruneActive and state.chainState != nil and
        state.chainState.bestHeight > MinBlocksToKeep:
      pruneHorizon = state.chainState.bestHeight - MinBlocksToKeep
    var notFound: seq[InvVector] = @[]
    var servedBlocks = 0
    var servedTxs = 0
    for item in msg.getData:
      if item.invType == invBlock or item.invType == invWitnessBlock:
        if pruneHorizon >= 0:
          let idxOpt = state.chainState.db.getBlockIndex(BlockHash(item.hash))
          if idxOpt.isSome and idxOpt.get().height < pruneHorizon:
            notFound.add(item)
            continue
        let blockOpt = state.chainState.db.getBlock(BlockHash(item.hash))
        if blockOpt.isSome:
          let blkMsg = newBlockMsg(blockOpt.get())
          try:
            await peer.sendMessage(blkMsg)
            servedBlocks.inc
          except CatchableError as e:
            debug "failed to serve block", peer = $peer, error = e.msg
        else:
          notFound.add(item)
      elif item.invType == invTx or item.invType == invWitnessTx:
        let txid = TxId(item.hash)
        let entryOpt = if state.mempool != nil: state.mempool.get(txid)
                      else: none(MempoolEntry)
        if entryOpt.isSome:
          let txMsg = newTxMsg(entryOpt.get().tx)
          try:
            await peer.sendMessage(txMsg)
            servedTxs.inc
          except CatchableError as e:
            debug "failed to serve tx", peer = $peer, error = e.msg
        else:
          notFound.add(item)
      else:
        # Unknown / unsupported inv type (compact-block, filtered-block, ...)
        notFound.add(item)
    if servedBlocks > 0 or servedTxs > 0:
      debug "served getdata", peer = $peer,
            blocks = servedBlocks, txs = servedTxs,
            notFound = notFound.len
    if notFound.len > 0:
      try:
        await peer.sendMessage(newNotFound(notFound))
      except CatchableError as e:
        debug "failed to send notfound", peer = $peer, error = e.msg

  of mkGetHeaders:
    # Serve headers to peers. Reference: bitcoin-core/src/net_processing.cpp
    # NetMsgType::GETHEADERS (line 4306). Locator is descending by height;
    # we reply with up to MaxHeadersPerMsg (2000) headers starting from the
    # block AFTER the latest known common ancestor.
    let req = msg.getHeaders
    if req.locatorHashes.len > MaxLocatorSz:
      warn "getheaders locator oversized", peer = $peer,
           size = req.locatorHashes.len
      return
    if state.chainState.bestHeight < 0:
      # Chain not initialised; reply with empty headers so the peer doesn't
      # treat us as unresponsive.
      try:
        await peer.sendMessage(newHeaders(@[]))
      except CatchableError:
        discard
      return

    var startHeight: int32
    let zeroHash = array[32, byte](default(array[32, byte]))
    if req.locatorHashes.len == 0:
      # Null locator: peer is asking for headers up to (and including) the
      # hashStop block.
      let bh = BlockHash(req.hashStop)
      var idxHeight: int32 = -1
      if state.syncManager != nil:
        let hOpt = state.syncManager.headerChain.getHeight(bh)
        if hOpt.isSome:
          idxHeight = hOpt.get()
      if idxHeight < 0:
        let idxOpt = state.chainState.db.getBlockIndex(bh)
        if idxOpt.isSome:
          idxHeight = idxOpt.get().height
      if idxHeight < 0:
        # Don't know the stop hash; nothing to do.
        return
      startHeight = idxHeight
    else:
      startHeight = findLocatorFork(state, req.locatorHashes) + 1

    var headers: seq[BlockHeader] = @[]
    var height = startHeight
    let stopHash = req.hashStop
    let stopIsNull = stopHash == zeroHash
    while headers.len < MaxHeadersPerMsg:
      let hdrOpt = activeChainHeaderAtHeight(state, height)
      if hdrOpt.isNone:
        break
      headers.add(hdrOpt.get())
      let hashOpt = activeChainHashAtHeight(state, height)
      if not stopIsNull and hashOpt.isSome and
         array[32, byte](hashOpt.get()) == stopHash:
        break
      height.inc
    try:
      await peer.sendMessage(newHeaders(headers))
      debug "served getheaders", peer = $peer,
            startHeight = startHeight, count = headers.len
    except CatchableError as e:
      debug "failed to send headers", peer = $peer, error = e.msg

  of mkGetBlocks:
    # Serve block-hash inv to peers. Reference: net_processing.cpp
    # NetMsgType::GETBLOCKS (line 4179). Up to 500 hashes starting at the
    # block AFTER the latest known common ancestor, stopping at hashStop.
    let req = msg.getBlocks
    if req.locatorHashes.len > MaxLocatorSz:
      warn "getblocks locator oversized", peer = $peer,
           size = req.locatorHashes.len
      return
    if state.chainState.bestHeight < 0:
      return

    let startHeight = findLocatorFork(state, req.locatorHashes) + 1
    var invItems: seq[InvVector] = @[]
    var height = startHeight
    let stopHash = req.hashStop
    let zeroHash = array[32, byte](default(array[32, byte]))
    let stopIsNull = stopHash == zeroHash
    let limit = MaxGetBlocksInvCount
    # Don't advertise blocks we don't actually have on disk yet (the header
    # chain may be ahead of the block tip during IBD).
    let maxServedHeight = state.chainState.bestHeight
    while invItems.len < limit and height <= maxServedHeight:
      let hashOpt = activeChainHashAtHeight(state, height)
      if hashOpt.isNone:
        break
      let bh = hashOpt.get()
      invItems.add(InvVector(invType: invBlock, hash: array[32, byte](bh)))
      if not stopIsNull and array[32, byte](bh) == stopHash:
        break
      height.inc
    if invItems.len > 0:
      try:
        await peer.sendMessage(newInv(invItems))
        debug "served getblocks", peer = $peer,
              startHeight = startHeight, count = invItems.len
      except CatchableError as e:
        debug "failed to send getblocks inv", peer = $peer, error = e.msg

  of mkGetAddr:
    # GetAddr is also handled in PeerManager.handleAddrInternal so the
    # response goes out before any user-level callback fires. This branch
    # is a defensive no-op so the dispatcher doesn't fall through to the
    # `else` and hit the unhandled-message log.
    discard

  of mkMempool:
    # BIP35: peer requests our mempool, respond with one or more inv
    # messages enumerating mempool txids. We use witness-tx inv (since we
    # advertise NodeWitness during handshake). Chunk to MaxInvPerMsg.
    #
    # Bitcoin Core gate (net_processing.cpp:4852-4863):
    #   if (!(peer.m_our_services & NODE_BLOOM) &&
    #       !pfrom.HasPermission(NetPermissionFlags::Mempool))
    #     -> drop, disconnect (unless NoBan).
    # Nimrod has no per-peer permission system, so we mirror only the
    # service-bit half: serve `mempool` iff WE advertised NODE_BLOOM in
    # our version (i.e. NIMROD_PEER_BLOOM_FILTERS is on).  Reading the
    # local advertisement flag rather than peer.services keeps the gate
    # symmetric with what we told the peer at handshake.
    if not peerBloomFiltersEnabled():
      debug "ignoring mempool request: NODE_BLOOM not advertised", peer = $peer
    elif state.mempool == nil:
      trace "mempool request before mempool init", peer = $peer
    else:
      var batch: seq[InvVector] = @[]
      var sent = 0
      {.gcsafe.}:
        for txid, _ in state.mempool.entries:
          batch.add(InvVector(invType: invWitnessTx, hash: array[32, byte](txid)))
          if batch.len >= MaxInvPerMsg:
            try:
              await peer.sendMessage(newInv(batch))
              sent += batch.len
            except CatchableError as e:
              debug "mempool inv send failed", peer = $peer, error = e.msg
              batch.setLen(0)
              break
            batch.setLen(0)
      if batch.len > 0:
        try:
          await peer.sendMessage(newInv(batch))
          sent += batch.len
        except CatchableError as e:
          debug "mempool inv send failed", peer = $peer, error = e.msg
      debug "served mempool inv to peer", peer = $peer, txCount = sent

  of mkPing:
    # Respond with pong
    discard

  of mkGetPkgTxns:
    # BIP-331: peer wants the ancestor package whose child has the supplied
    # wtxid. Look the child up in our mempool, walk its ancestors, and reply
    # with `pkgtxns` (parents first, child last, capped at MaxPkgTxnsCount).
    if state.mempool == nil:
      trace "getpkgtxns before mempool init", peer = $peer
    else:
      var childTxid: TxId
      var childFound = false
      let target = msg.getPkgTxns.childWtxid
      {.gcsafe.}:
        for txid, entry in state.mempool.entries:
          if array[32, byte](entry.tx.wtxid()) == target:
            childTxid = txid
            childFound = true
            break
      if not childFound:
        trace "getpkgtxns: child wtxid not in mempool",
              peer = $peer, wtxid = target
      else:
        # Build parents-first topo order: ancestors from calculateAncestors
        # are unordered, so we sort by ancestorCount as a coarse proxy.
        var pkgTxs: seq[Transaction]
        var ancestorIds: seq[TxId]
        {.gcsafe.}:
          let ancestors = state.mempool.calculateAncestors(
            state.mempool.entries[childTxid].tx)
          for aid in ancestors:
            if aid != childTxid:
              ancestorIds.add(aid)
        # Sort ancestors so lowest ancestorCount comes first (i.e. roots).
        ancestorIds.sort(proc(a, b: TxId): int =
          let ea = state.mempool.entries[a]
          let eb = state.mempool.entries[b]
          cmp(ea.ancestorCount, eb.ancestorCount))
        for aid in ancestorIds:
          pkgTxs.add(state.mempool.entries[aid].tx)
          if pkgTxs.len >= MaxPkgTxnsCount - 1:
            break
        pkgTxs.add(state.mempool.entries[childTxid].tx)
        try:
          await peer.sendMessage(newPkgTxns(pkgTxs))
          debug "served pkgtxns", peer = $peer,
                child = childTxid, txCount = pkgTxs.len
        except CatchableError as e:
          debug "pkgtxns send failed", peer = $peer, error = e.msg

  of mkPkgTxns:
    # BIP-331: peer delivered an ancestor package. Try to accept each tx in
    # order (parents first); skip-don't-fail on individual errors.
    if state.mempool == nil:
      trace "pkgtxns before mempool init", peer = $peer
    else:
      var accepted = 0
      for tx in msg.pkgTxns.transactions:
        {.gcsafe.}:
          try:
            let r = state.mempool.acceptTransaction(tx, state.crypto)
            if r.isOk: inc accepted
          except CatchableError:
            discard
          except Exception:
            discard
      debug "processed pkgtxns",
            peer = $peer, total = msg.pkgTxns.transactions.len,
            accepted = accepted

  else:
    discard

proc messageCallback(state: NodeState): peer.PeerCallback =
  ## Create message callback for peer manager
  proc callback(peer: Peer, msg: P2PMessage): Future[void] {.async.} =
    await handleMessage(state, peer, msg)
  return callback

proc setupSignalHandlers*() =
  ## Setup SIGINT/SIGTERM handlers for graceful shutdown, plus SIGHUP for
  ## log-file reopen (rotation-friendly; matches Bitcoin Core's
  ## `OpenDebugLog` reopen-on-rotate behaviour).
  proc sigHupHandler(sig: cint) {.noconv.} =
    # Best-effort log reopen; never modifies node state. Safe for signal
    # context because reopenLog uses only POSIX open/dup2/close.
    reopenLog()

  proc sigHandler(sig: cint) {.noconv.} =
    echo "\nReceived signal " & $sig & ", shutting down..."

    # Always remove the PID file we wrote on launch — even if globalNodeState
    # is nil (early-startup crash path).
    removePidFile()

    if globalNodeState != nil:
      globalNodeState.running = false

      # If in IBD mode, flush the write batch before closing (WAL is disabled
      # during IBD so unflushed blocks are not durable until stopIBD is called)
      if globalNodeState.chainState != nil and globalNodeState.chainState.ibdMode:
        info "flushing IBD batch before shutdown"
        globalNodeState.chainState.stopIBD()

      # Flush UTXO cache
      if globalNodeState.chainState != nil:
        info "flushing UTXO cache"
        globalNodeState.chainState.flushCache()

      # Stop REST server (best-effort: just flips the running flag; the
      # listener exits the next accept(). The thread storage on
      # NodeState.restThread is freed when the NodeState ref drops).
      if globalNodeState.restServer != nil:
        info "stopping REST server"
        globalNodeState.restServer.stop()

      # Stop RPC server and remove cookie file
      if globalNodeState.rpcServer != nil:
        info "stopping RPC server"
        globalNodeState.rpcServer.stop()
        let cookiePath = globalNodeState.config.dataDir /
                         globalNodeState.config.network / ".cookie"
        if fileExists(cookiePath):
          removeFile(cookiePath)
          info "removed RPC cookie file", path = cookiePath

      # Save fee estimates
      if globalNodeState.feeEstimator != nil:
        let feePath = globalNodeState.config.dataDir /
                      globalNodeState.config.network / "fee_estimates.json"
        info "saving fee estimates", path = feePath
        globalNodeState.feeEstimator.saveFeeEstimates(feePath)

      # Dump mempool to mempool.dat (Bitcoin Core compatible).
      if globalNodeState.mempool != nil:
        let mempoolPath = globalNodeState.config.dataDir /
                          globalNodeState.config.network / CurrentMempoolDumpFile
        info "saving mempool", path = mempoolPath
        discard dumpMempool(globalNodeState.mempool, mempoolPath)

      # Disconnect peers
      if globalNodeState.peerManager != nil:
        info "disconnecting peers"
        globalNodeState.peerManager.stop()

      # Close database
      if globalNodeState.chainState != nil:
        info "closing database"
        globalNodeState.chainState.close()

      info "shutdown complete"

    quit(0)

  signal(SIGINT, sigHandler)
  signal(SIGTERM, sigHandler)
  signal(SIGHUP, sigHupHandler)

proc generateCookieFile*(dataDir: string): string =
  ## Generate a 32-byte random cookie, write "__cookie__:<hex>" to
  ## {dataDir}/.cookie with mode 0o600, and return the hex password.
  ## Mirrors Bitcoin Core's GenerateAuthCookie() in httpserver.cpp.
  var rawBytes: array[32, byte]
  if not urandom(rawBytes):
    raise newException(IOError, "failed to read random bytes from system RNG")

  var hexPass = ""
  for b in rawBytes:
    hexPass.add(toHex(int(b), 2).toLowerAscii())

  let cookiePath = dataDir / ".cookie"
  let cookieContent = "__cookie__:" & hexPass
  writeFile(cookiePath, cookieContent)
  setFilePermissions(cookiePath, {fpUserRead, fpUserWrite})

  hexPass

proc runBlockImport*(config: NimrodConfig) =
  ## Import blocks from blk*.dat files or framed stdin.
  ## blk*.dat format: [4B magic LE][4B size LE][size bytes raw block] repeated
  ## stdin framed:    [4B height LE][4B size LE][size bytes raw block] repeated
  let params = getConsensusParams(config)
  let networkDir = config.dataDir / config.network
  if not dirExists(networkDir):
    createDir(networkDir)

  echo "nimrod block import mode"
  echo "Network: " & config.network

  # Open chainstate
  var cs = newChainState(networkDir / "chainstate", params)
  if config.ibdFlushInterval > 0:
    cs.ibdDiskFlushInterval = config.ibdFlushInterval

  # Initialize genesis if needed
  if cs.bestHeight < 0:
    let genesis = buildGenesisBlock(params)
    let connectResult = cs.connectBlock(genesis, 0)
    if not connectResult.isOk:
      echo "Failed to connect genesis block: " & $connectResult.error
      quit(1)

  let startHeight = cs.bestHeight
  echo "Chain tip at height " & $startHeight

  cs.startIBD()

  if config.importBlocks == "-":
    # Read framed format from stdin
    echo "Reading blocks from stdin (framed format)..."
    var imported = 0
    let importStart = getMonoTime()
    var batchStart = getMonoTime()

    while true:
      # Read frame header: [4B height LE][4B size LE]
      var frameHeader: array[8, byte]
      let headerRead = stdin.readBuffer(addr frameHeader[0], 8)
      if headerRead < 8:
        echo "End of stdin stream."
        break

      let frameHeight = int32(
        uint32(frameHeader[0]) or
        (uint32(frameHeader[1]) shl 8) or
        (uint32(frameHeader[2]) shl 16) or
        (uint32(frameHeader[3]) shl 24)
      )
      let frameSize = int(
        uint32(frameHeader[4]) or
        (uint32(frameHeader[5]) shl 8) or
        (uint32(frameHeader[6]) shl 16) or
        (uint32(frameHeader[7]) shl 24)
      )

      if frameSize <= 0 or frameSize > 4_000_000:
        echo "Invalid frame size " & $frameSize & " at height " & $frameHeight
        break

      # Skip blocks we already have
      if frameHeight <= startHeight:
        var skipBuf = newSeq[byte](frameSize)
        let skipped = stdin.readBuffer(addr skipBuf[0], frameSize)
        if skipped < frameSize:
          break
        continue

      # Read block data
      var blockData = newSeq[byte](frameSize)
      let bytesRead = stdin.readBuffer(addr blockData[0], frameSize)
      if bytesRead < frameSize:
        echo "Truncated block data at height " & $frameHeight
        break

      let blk = deserializeBlock(blockData)

      # Validate
      let checkResult = checkBlock(blk, params)
      if not checkResult.isOk:
        echo "Block validation failed at height " & $frameHeight & ": " & $checkResult.error
        break

      # Connect
      let connectResult = cs.connectBlockIBD(blk, frameHeight)
      if not connectResult.isOk:
        echo "Block connect failed at height " & $frameHeight & ": " & $connectResult.error
        break

      imported += 1

      if imported mod 1000 == 0:
        let elapsed = (getMonoTime() - batchStart).inMilliseconds.float / 1000.0
        let bps = 1000.0 / elapsed
        let totalElapsed = (getMonoTime() - importStart).inMilliseconds.float / 1000.0
        echo "Import progress: height " & $frameHeight &
             " (" & $imported & " blocks, " &
             $(int(bps)) & " blocks/sec, " &
             $(int(bps * 60.0)) & " blocks/min, " &
             "elapsed " & $(int(totalElapsed)) & "s)"
        batchStart = getMonoTime()

    let totalElapsed = (getMonoTime() - importStart).inMilliseconds.float / 1000.0
    if imported > 0:
      let bps = float(imported) / totalElapsed
      echo "Import complete: " & $imported & " blocks in " &
           $(int(totalElapsed)) & "s (" &
           $(int(bps)) & " blocks/sec, " &
           $(int(bps * 60.0)) & " blocks/min)"

  else:
    # Read from blk*.dat directory
    let blocksDir = config.importBlocks
    let expectedMagic = params.networkMagic

    echo "Scanning blk*.dat files in " & blocksDir & " ..."

    # Detect XOR obfuscation key (Bitcoin Core 28.0+)
    var xorKey: array[8, byte]
    block:
      let firstFile = blocksDir / "blk00000.dat"
      if fileExists(firstFile):
        let f = open(firstFile)
        var hdr: array[16, byte]
        let n = f.readBuffer(addr hdr[0], 16)
        f.close()
        if n == 16:
          if hdr[0] != expectedMagic[0] or hdr[1] != expectedMagic[1] or
             hdr[2] != expectedMagic[2] or hdr[3] != expectedMagic[3]:
            # Derive key[0..4] from magic
            for i in 0..3:
              xorKey[i] = hdr[i] xor expectedMagic[i]
            # Derive key[4..8] from offset 12..16 (prevhash[0..4] = 0 for genesis)
            for i in 0..3:
              xorKey[4 + i] = hdr[12 + i]
            echo "Detected XOR obfuscation key: " &
                 xorKey[0].toHex & xorKey[1].toHex & xorKey[2].toHex & xorKey[3].toHex &
                 xorKey[4].toHex & xorKey[5].toHex & xorKey[6].toHex & xorKey[7].toHex

    proc xorDeobfuscate(data: var openArray[byte], fileOffset: int64, key: array[8, byte]) =
      if key == default(array[8, byte]):
        return
      for i in 0 ..< data.len:
        data[i] = data[i] xor key[int((fileOffset + int64(i)) mod 8)]

    # Build hash -> (fileNum, offset, size) index
    var index = initTable[BlockHash, tuple[fileNum: int, offset: int64, size: int]]()
    var fileNum = 0

    while true:
      let filePath = blocksDir / "blk" & align($fileNum, 5, '0') & ".dat"
      if not fileExists(filePath):
        break

      let fileData = readFile(filePath)
      let fileLen = fileData.len
      var pos = 0
      var blocksInFile = 0

      while pos + 8 <= fileLen:
        # Read and deobfuscate header
        var hdr: array[8, byte]
        copyMem(addr hdr[0], unsafeAddr fileData[pos], 8)
        xorDeobfuscate(hdr, int64(pos), xorKey)

        # Check zero padding
        if hdr[0] == 0 and hdr[1] == 0 and hdr[2] == 0 and hdr[3] == 0:
          break

        # Check magic
        if hdr[0] != expectedMagic[0] or hdr[1] != expectedMagic[1] or
           hdr[2] != expectedMagic[2] or hdr[3] != expectedMagic[3]:
          echo "Bad magic at blk" & align($fileNum, 5, '0') & ".dat offset " & $pos
          break

        let size = int(
          uint32(hdr[4]) or
          (uint32(hdr[5]) shl 8) or
          (uint32(hdr[6]) shl 16) or
          (uint32(hdr[7]) shl 24)
        )

        if size <= 0 or size > 4_000_000:
          echo "Invalid block size " & $size & " at offset " & $pos
          break

        let blockOffset = pos + 8

        # Read and deobfuscate 80-byte header to get hash
        var headerBytes = newSeq[byte](80)
        copyMem(addr headerBytes[0], unsafeAddr fileData[blockOffset], 80)
        xorDeobfuscate(headerBytes, int64(blockOffset), xorKey)
        let header = deserializeBlockHeader(headerBytes)
        let headerSer = serialize(header)
        let hash = BlockHash(doubleSha256(headerSer))

        index[hash] = (fileNum: fileNum, offset: int64(blockOffset), size: size)

        blocksInFile += 1
        pos = blockOffset + size

      echo "Scanned blk" & align($fileNum, 5, '0') & ".dat: " &
           $blocksInFile & " blocks (total: " & $index.len & ")"
      fileNum += 1

    if fileNum == 0:
      echo "No blk*.dat files found in " & blocksDir
      quit(1)

    echo "Block index built: " & $index.len & " blocks from " & $fileNum & " files"

    # Process blocks in height order
    var height = startHeight + 1
    var imported = 0
    let importStart = getMonoTime()
    var batchStart = getMonoTime()

    # Cache for file data
    var cachedFileNum = -1
    var cachedFileData: string

    while true:
      let hashOpt = cs.db.getBlockHashByHeight(height)
      if hashOpt.isNone:
        echo "No header at height " & $height & ". Imported " & $imported & " blocks."
        break

      let hash = hashOpt.get()
      if hash notin index:
        echo "Block at height " & $height & " not found in blk files. Stopping."
        break

      let loc = index[hash]

      # Read and deobfuscate block data
      if loc.fileNum != cachedFileNum:
        let filePath = blocksDir / "blk" & align($loc.fileNum, 5, '0') & ".dat"
        cachedFileData = readFile(filePath)
        cachedFileNum = loc.fileNum

      var blockData = newSeq[byte](loc.size)
      copyMem(addr blockData[0], unsafeAddr cachedFileData[loc.offset], loc.size)
      xorDeobfuscate(blockData, loc.offset, xorKey)

      let blk = deserializeBlock(blockData)

      # Validate
      let checkResult = checkBlock(blk, params)
      if not checkResult.isOk:
        echo "Block validation failed at height " & $height & ": " & $checkResult.error
        break

      # Connect
      let connectResult = cs.connectBlockIBD(blk, height)
      if not connectResult.isOk:
        echo "Block connect failed at height " & $height & ": " & $connectResult.error
        break

      imported += 1
      height += 1

      if imported mod 1000 == 0:
        let elapsed = (getMonoTime() - batchStart).inMilliseconds.float / 1000.0
        let bps = 1000.0 / elapsed
        let totalElapsed = (getMonoTime() - importStart).inMilliseconds.float / 1000.0
        echo "Import progress: height " & $(height - 1) &
             " (" & $imported & " blocks, " &
             $(int(bps)) & " blocks/sec, " &
             $(int(bps * 60.0)) & " blocks/min, " &
             "elapsed " & $(int(totalElapsed)) & "s)"
        batchStart = getMonoTime()

    let totalElapsed = (getMonoTime() - importStart).inMilliseconds.float / 1000.0
    if imported > 0:
      let bps = float(imported) / totalElapsed
      echo "Import complete: " & $imported & " blocks in " &
           $(int(totalElapsed)) & "s (" &
           $(int(bps)) & " blocks/sec, " &
           $(int(bps * 60.0)) & " blocks/min)"

  cs.stopIBD()
  echo "Import finished. Tip at height " & $cs.bestHeight

proc metricsHandler(state: NodeState, transp: StreamTransport) {.async.} =
  ## Handle a single Prometheus metrics request
  try:
    # Read HTTP request (just consume it)
    var buf = newString(4096)
    discard await transp.readOnce(addr buf[0], 4096)

    let height = state.chainState.bestHeight
    let peers = state.peerManager.connectedPeerCount()
    let mempoolCount = state.mempool.count()

    let body = "# HELP bitcoin_blocks_total Current block height\n" &
               "# TYPE bitcoin_blocks_total gauge\n" &
               "bitcoin_blocks_total " & $height & "\n" &
               "# HELP bitcoin_peers_connected Number of connected peers\n" &
               "# TYPE bitcoin_peers_connected gauge\n" &
               "bitcoin_peers_connected " & $peers & "\n" &
               "# HELP bitcoin_mempool_size Mempool transaction count\n" &
               "# TYPE bitcoin_mempool_size gauge\n" &
               "bitcoin_mempool_size " & $mempoolCount & "\n"

    let response = "HTTP/1.1 200 OK\r\n" &
                   "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n" &
                   "Content-Length: " & $body.len & "\r\n" &
                   "Connection: close\r\n\r\n" & body

    discard await transp.write(response)
  except CatchableError:
    discard

  await transp.closeWait()

proc startMetricsServer(state: NodeState, port: uint16) {.async.} =
  ## Start Prometheus metrics HTTP server.
  ## Bind failures (e.g. EADDRINUSE) MUST NOT crash the node — degrade
  ## to "metrics disabled" and let the node keep serving RPC + P2P.
  ## The previous behaviour let TransportOsError escape to asyncSpawn,
  ## which raised FutureDefect on the chronos event loop and killed the
  ## process (regression caught by tools/smoke-harness.sh when port 9332
  ## was already held by another fleet node — e.g. mainnet blockbrew).
  let ta = initTAddress("0.0.0.0", Port(port))
  var server: StreamServer
  try:
    server = createStreamServer(ta, flags = {ReuseAddr})
  except CatchableError as e:
    error "metrics server bind failed; metrics disabled",
          port = port, error = e.msg
    return

  info "Prometheus metrics server started", port = port

  while state.running:
    try:
      let transp = await server.accept()
      asyncSpawn metricsHandler(state, transp)
    except CatchableError as e:
      if state.running:
        error "Metrics server error", error = e.msg

  server.close()

proc restThreadMain(rest: RestServer) {.thread.} =
  ## Thread entry point for the REST listener.  Mirrors rpcThreadMain in
  ## src/rpc/rpc_thread.nim — chronos dispatchers are thread-local, so the
  ## REST server gets its own event loop on this thread and is not blocked
  ## by main-thread block validation or by the RPC thread.
  {.gcsafe.}:
    try:
      waitFor rest.start()
    except CatchableError as e:
      error "REST thread crashed", error = e.msg

proc startNode*(config: NimrodConfig) {.async.} =
  ## Start the node
  ## Init order: db -> chainstate -> mempool -> peermanager -> sync -> fee estimator -> RPC -> P2P
  let params = getConsensusParams(config)

  # BIP-159: latch the NODE_NETWORK_LIMITED advertisement gate from the
  # parsed `pruneTarget` so the version handshake correctly signals
  # limited-archive serving when prune mode is enabled.  Mirrors Core's
  # `init.cpp` (`nLocalServices |= NODE_NETWORK_LIMITED` when
  # `IsPruneMode()` is true).
  setPruneModeAdvertise(config.pruneTarget > 0)

  # Create data directory
  if not dirExists(config.dataDir):
    createDir(config.dataDir)

  let networkDir = config.dataDir / config.network
  if not dirExists(networkDir):
    createDir(networkDir)

  info "starting nimrod",
    version = NimrodVersion,
    network = config.network,
    dataDir = config.dataDir,
    rpcPort = config.rpcPort,
    p2pPort = config.p2pPort

  echo "nimrod v" & NimrodVersion
  echo "Network: " & config.network
  echo "Data directory: " & config.dataDir
  echo "P2P port: " & $config.p2pPort
  if config.rpcEnabled:
    echo "RPC port: " & $config.rpcPort

  # Initialize subsystems
  var state = NodeState(
    config: config,
    params: params,
    running: true,
    recentlyRejected: initHashSet[TxId](),
    orphanPool: newOrphanPool()
  )
  {.gcsafe.}:
    globalNodeState = state

  # 1. Initialize crypto engine
  info "initializing crypto engine"
  state.crypto = newCryptoEngine()

  # 2. Open database and chainstate
  info "opening database", path = networkDir / "chainstate"
  state.chainState = newChainState(networkDir / "chainstate", params)
  if config.ibdFlushInterval > 0:
    state.chainState.ibdDiskFlushInterval = config.ibdFlushInterval

  # Check for genesis block
  if state.chainState.bestHeight < 0:
    info "initializing genesis block"
    let genesis = buildGenesisBlock(params)
    let connectResult = state.chainState.connectBlock(genesis, 0)
    if not connectResult.isOk:
      error "failed to connect genesis block", error = connectResult.error
      quit(1)

  info "chainstate loaded",
    height = state.chainState.bestHeight,
    bestBlock = $state.chainState.bestBlockHash

  # Optional one-shot UTXO snapshot load (assumeUTXO). Only meaningful on a
  # near-empty chainstate; loading on top of an existing tip would corrupt the
  # UTXO set. We refuse if the chain has already advanced past genesis.
  if config.loadSnapshot.len > 0:
    if state.chainState.bestHeight > 0:
      warn "ignoring --load-snapshot on populated chainstate",
        height = state.chainState.bestHeight
    else:
      info "loading UTXO snapshot", path = config.loadSnapshot
      let r = loadSnapshot(
        config.loadSnapshot,
        state.chainState,
        params,
        params.assumeutxoData
      )
      if not r.success:
        error "snapshot load failed", error = r.error
        quit(1)
      info "snapshot loaded",
        coins = r.coinsLoaded,
        height = state.chainState.bestHeight,
        bestBlock = $state.chainState.bestBlockHash

  # 2c. Initialize block-file manager + production prune driver. Even when
  # block bodies live in RocksDB (the production layout — flat blk*.dat
  # files are never written), the BlockFileManager owns the prune
  # bookkeeping (target, mode, getPruneHeight) that the RPC layer reads.
  # The Pruner owns the actual delete loop (cfBlocks delete + rev*.dat
  # unlink). Closes Cat-pruning RED for nimrod from
  # CORE-PARITY-AUDIT/_pruning-cross-impl-audit-2026-05-05.md.
  state.blockFileManager = newBlockFileManager(networkDir, params, state.chainState.db.db)
  if config.pruneTarget > 0:
    state.pruner = newPruner(
      state.chainState,
      state.blockFileManager,
      params,
      config.pruneTarget
    )
    let mode = case state.pruner.mode
      of pmDisabled: "disabled"
      of pmManualOnly: "manual-only (--prune=1)"
      of pmAutomatic: "automatic"
    info "prune subsystem enabled",
         mode = mode,
         target_bytes = state.pruner.currentTargetBytes(),
         prune_height = state.pruner.currentPruneHeight()
  else:
    state.pruner = nil
    info "prune subsystem disabled (no --prune flag)"

  # 3. Initialize mempool
  info "initializing mempool"
  state.mempool = newMempool(state.chainState, params)

  # 3a. Restore mempool from prior shutdown dump (mempool.dat). Best-effort:
  # any tx that fails to re-accept is dropped silently, matching Core.
  block restoreMempool:
    let mempoolDumpPath = networkDir / CurrentMempoolDumpFile
    if fileExists(mempoolDumpPath):
      {.gcsafe.}:
        try:
          let r = loadMempool(state.mempool, mempoolDumpPath, state.crypto)
          if r.isSome:
            let counts = r.get()
            info "mempool.dat loaded",
                 succeeded = counts.succeeded, failed = counts.failed,
                 expired = counts.expired, alreadyThere = counts.alreadyThere
        except CatchableError as e:
          warn "loadMempool raised, continuing", error = e.msg
        except Exception as e:
          warn "loadMempool raised (non-Catchable), continuing", error = e.msg

  # 4. Initialize fee estimator
  info "initializing fee estimator"
  state.feeEstimator = newFeeEstimator()
  let feeEstimatesPath = networkDir / "fee_estimates.json"
  state.feeEstimator.loadFeeEstimates(feeEstimatesPath)

  # 5. Initialize peer manager
  info "initializing peer manager"
  state.peerManager = newPeerManager(params, maxOut = config.maxConnections div 16, maxIn = config.maxConnections - config.maxConnections div 16, dataDir = networkDir)
  state.peerManager.updateHeight(state.chainState.bestHeight)
  state.peerManager.setMessageCallback(messageCallback(state))

  # 6. Initialize sync manager
  info "initializing sync manager"
  state.syncManager = newSyncManager(state.peerManager, state.chainState.db, params, state.chainState, config.numVerifyWorkers)
  state.syncManager.chainTip = state.chainState.bestBlockHash
  state.syncManager.chainTipHeight = state.chainState.bestHeight

  # 7. Start RPC server
  if config.rpcEnabled:
    info "starting RPC server", port = config.rpcPort

    # Generate cookie auth — always written so that local tooling can connect
    # even when --rpcuser/--rpcpassword are not set.
    let cookiePass = generateCookieFile(networkDir)
    let cookiePath = networkDir / ".cookie"
    info "wrote RPC cookie file", path = cookiePath

    state.rpcServer = newRpcServer(
      config.rpcPort,
      state.chainState,
      state.mempool,
      state.peerManager,
      state.feeEstimator,
      params,
      config.rpcUser,
      config.rpcPassword,
      cookiePass
    )
    # Wire the BlockFileManager so getblockchaininfo and pruneblockchain
    # answer correctly. The handler also reads `pruner` (when non-nil) for
    # the actual delete path; see handlePruneBlockchain in src/rpc/server.nim.
    state.rpcServer.blockFileManager = state.blockFileManager
    state.rpcServer.pruner = state.pruner
    # Run RPC on a dedicated OS thread with its own chronos event loop so that
    # CPU-heavy block validation on the main thread does not block RPC accept
    # or response. See src/rpc/rpc_thread.nim for rationale and known v1 caveats.
    #
    # IMPORTANT: keep the handle alive on `state` for the process lifetime.
    # Discarding the result frees the underlying `Thread[RpcServer]` storage
    # while the freshly-spawned pthread is still reading from `addr(t)`,
    # which manifests as a SIGSEGV ("Attempt to read from nil") on startup
    # (deterministic on regtest, flaky on testnet/mainnet depending on how
    # quickly the new pthread is scheduled).  Holding the handle on
    # `NodeState` keeps it pinned for the lifetime of the node.
    state.rpcThread = startRpcThread(state.rpcServer)

  # 7a. Optional BIP-157 basic block-filter index. Without --blockfilterindex
  # the field stays nil and /rest/blockfilter[headers] returns
  # "Index is not enabled for filtertype basic" (Core parity).
  #
  # NOTE: backfill of historical blocks into this index is not yet wired
  # into the IBD path in nimrod (the index module exists and can ingest
  # `BlockInfo` via processBlock, but the connect-block hook hasn't been
  # added). Until that lands, the REST endpoints will return "Filter not
  # found. Block filters are still in the process of being indexed" for
  # most heights — same wire shape Core emits during its own backfill.
  # The listener and routing are still useful: they're what the audit
  # called out as the dead-code surface.
  if config.blockfilterindex:
    info "initializing blockfilterindex (basic)"
    state.blockFilterIndex = newBlockFilterIndex(
      state.chainState.db.db, networkDir, bftBasic, enabled = true)
  else:
    state.blockFilterIndex = nil

  # 7c. Start REST HTTP server (default OFF, --rest gate, Core parity).
  if config.restEnabled:
    let restPort =
      if config.restPort != 0: config.restPort
      else: uint16(int(config.rpcPort) + 1000)
    info "starting REST server", port = restPort
    state.restServer = newRestServer(
      restPort,
      state.chainState,
      state.mempool,
      params,
      txIndex = nil,
      filterIndex = state.blockFilterIndex
    )
    # Same OS-thread model as the RPC server: each chronos dispatcher is
    # thread-local, so the REST listener gets its own event loop and is
    # not blocked by main-thread verifyScripts batches. Keep the thread
    # storage on `state` so it stays pinned for process lifetime — same
    # SIGSEGV trap rpc_thread.nim documents.
    createThread(state.restThread, restThreadMain, state.restServer)

  # 7b. Start Prometheus metrics server
  if config.metricsPort > 0:
    info "starting metrics server", port = config.metricsPort
    asyncSpawn startMetricsServer(state, config.metricsPort)

  # 8. Start P2P listener
  info "starting P2P listener", port = config.p2pPort, bindAddr = config.bindAddr
  await state.peerManager.startListener(config.bindAddr, config.p2pPort)

  # 9. Start outbound connections
  info "connecting to peers"
  await state.peerManager.startOutboundConnections()

  # 10. Start sync loop
  info "starting sync"
  asyncSpawn state.syncManager.syncLoop()

  # 11. Start peer manager main loop
  asyncSpawn state.peerManager.mainLoop()

  # Main loop - keep running until shutdown
  while state.running:
    # Update peer manager with our height
    state.peerManager.updateHeight(state.chainState.bestHeight)

    # Expire old mempool transactions periodically
    state.mempool.expire()

    # Auto-prune trigger (no-op unless --prune=N with N >= 550 was set).
    # Throttled internally by AutoPruneCheckInterval so this is cheap.
    # Manual mode (--prune=1) is honored: autoPruneIfNeeded short-circuits.
    if state.pruner != nil:
      try:
        state.pruner.autoPruneIfNeeded()
      except CatchableError as e:
        warn "auto-prune failed; will retry next heartbeat", error = e.msg

    await sleepAsync(10000)  # 10 second heartbeat

proc rpcCall*(config: NimrodConfig, `method`: string, params: JsonNode): Future[JsonNode] {.async.} =
  ## Make an RPC call to a running node
  let host = "127.0.0.1"
  let port = config.rpcPort

  # Build JSON-RPC request
  let request = %*{
    "jsonrpc": "2.0",
    "id": 1,
    "method": `method`,
    "params": params
  }

  let body = $request

  # Build HTTP request
  var httpRequest = "POST / HTTP/1.1\r\n"
  httpRequest &= "Host: " & host & ":" & $port & "\r\n"
  httpRequest &= "Content-Type: application/json\r\n"
  httpRequest &= "Content-Length: " & $body.len & "\r\n"

  # Add auth if configured
  if config.rpcUser != "" and config.rpcPassword != "":
    let auth = base64.encode(config.rpcUser & ":" & config.rpcPassword)
    httpRequest &= "Authorization: Basic " & auth & "\r\n"

  httpRequest &= "\r\n"
  httpRequest &= body

  # Connect and send
  let ta = initTAddress(host, Port(port))
  var transp: StreamTransport

  try:
    transp = await connect(ta)
    discard await transp.write(httpRequest)

    # Read response headers
    var responseHeaders = ""
    var contentLength = 0

    while true:
      let line = await transp.readLine()
      if line.len == 0:
        break
      responseHeaders &= line & "\r\n"
      if line.toLowerAscii().startsWith("content-length:"):
        contentLength = parseInt(line.split(":")[1].strip())

    # Read response body
    if contentLength > 0:
      let responseBody = await transp.read(contentLength)
      let responseStr = cast[string](responseBody)
      let response = parseJson(responseStr)

      if response.hasKey("error") and response["error"].kind != JNull:
        let errMsg = response["error"]["message"].getStr()
        raise newException(IOError, errMsg)

      return response["result"]
    else:
      raise newException(IOError, "empty response from server")

  except CatchableError as e:
    raise newException(IOError, "RPC call failed: " & e.msg)
  finally:
    if transp != nil:
      await transp.closeWait()

proc runCommand(cmd: Command, config: NimrodConfig, args: seq[string]) {.async.} =
  ## Run a non-start command via RPC
  case cmd
  of cmdStop:
    try:
      discard await rpcCall(config, "stop", newJArray())
      echo "Stop command sent"
    except IOError as e:
      echo "Error: " & e.msg

  of cmdGetInfo:
    try:
      let info = await rpcCall(config, "getblockchaininfo", newJArray())
      echo "Chain: " & info["chain"].getStr()
      echo "Blocks: " & $info["blocks"].getInt()
      echo "Headers: " & $info["headers"].getInt()
      echo "Best block: " & info["bestblockhash"].getStr()
      echo "Difficulty: " & $info["difficulty"].getFloat()
      echo "Chain work: " & info["chainwork"].getStr()
    except IOError as e:
      echo "Error: " & e.msg
      echo "Is nimrod running?"

  of cmdGetBlock:
    if args.len < 1:
      echo "Usage: nimrod getblock <blockhash>"
      quit(1)
    try:
      let params = %*[args[0], 1]  # verbosity 1
      let blk = await rpcCall(config, "getblock", params)
      echo pretty(blk)
    except IOError as e:
      echo "Error: " & e.msg

  of cmdSendRawTx:
    if args.len < 1:
      echo "Usage: nimrod sendrawtransaction <hex>"
      quit(1)
    try:
      let params = %*[args[0]]
      let txid = await rpcCall(config, "sendrawtransaction", params)
      echo txid.getStr()
    except IOError as e:
      echo "Error: " & e.msg

  of cmdGetBalance:
    try:
      let balance = await rpcCall(config, "getbalance", newJArray())
      echo $balance.getFloat() & " BTC"
    except IOError as e:
      echo "Error: " & e.msg

  of cmdSendTo:
    if args.len < 2:
      echo "Usage: nimrod sendtoaddress <address> <amount>"
      quit(1)
    try:
      let params = %*[args[0], parseFloat(args[1])]
      let txid = await rpcCall(config, "sendtoaddress", params)
      echo txid.getStr()
    except IOError as e:
      echo "Error: " & e.msg

  of cmdGetNewAddress:
    try:
      let address = await rpcCall(config, "getnewaddress", newJArray())
      echo address.getStr()
    except IOError as e:
      echo "Error: " & e.msg

  of cmdStart, cmdHelp, cmdVersion:
    discard  # Handled elsewhere

proc applyReindex(config: NimrodConfig) =
  ## --reindex (HONEST PROGRESS): wipe the chainstate dir so that the next
  ## startup re-runs IBD from genesis. This is intentionally NARROWER than
  ## Bitcoin Core's full -reindex which also re-scans `blk*.dat`. Nimrod
  ## doesn't store undisturbed block files separately during normal sync —
  ## the chainstate IS the canonical store — so wiping chainstate is the
  ## meaningful operation we can perform without inventing a new on-disk
  ## format. Documented as such in --help.
  let networkDir = config.dataDir / config.network
  let chainstateDir = networkDir / "chainstate"
  if dirExists(chainstateDir):
    echo "[--reindex] removing " & chainstateDir
    try:
      removeDir(chainstateDir)
    except OSError as e:
      echo "[--reindex] WARNING: failed to remove chainstate: " & e.msg
      quit(1)
  # Clear stray files that would otherwise drift from a fresh chainstate.
  for stale in ["fee_estimates.json", "mempool.dat"]:
    let p = networkDir / stale
    if fileExists(p):
      try: removeFile(p)
      except OSError: discard
  echo "[--reindex] chainstate cleared; node will resync from genesis"

proc operationalSetup(config: var NimrodConfig) =
  ## Apply daemonization, log redirection, PID-file, debug-topic and ready-FD
  ## wiring.  Modifies `config` in-place to fill defaults (e.g. derived PID
  ## path).  Called from `main()` between argument parsing and node start.
  ## Order matters:
  ##   1) reindex wipe — must happen before chainstate is opened by startNode.
  ##   2) daemonize    — must happen before any long-lived FDs are opened.
  ##   3) log redirect — must happen after daemonize so the new stdio is set.
  ##   4) PID file     — must happen after daemonize so we record the daemon
  ##                     PID, not the parent's.
  ##   5) debug cats   — runtime-only, order doesn't matter.
  ##   6) ready FD     — happens after the main loop is running (in startNode).

  # Make sure dataDir exists so derived paths (PID, log) work even before
  # startNode runs.
  if not dirExists(config.dataDir):
    createDir(config.dataDir)
  let networkDir = config.dataDir / config.network
  if not dirExists(networkDir):
    createDir(networkDir)

  # 1) reindex
  if config.reindex:
    applyReindex(config)

  # Resolve default PID and log paths once (so the daemon path uses the
  # same file the parent advertised).
  if config.pidFile.len == 0:
    config.pidFile = config.dataDir / "nimrod.pid"

  let derivedLogPath =
    if config.logFile.len > 0: config.logFile
    elif config.daemon and not config.printToConsole:
      networkDir / "debug.log"
    else: ""

  # 2) daemonize
  if config.daemon:
    # Pass derived log path so the daemon's stdio go directly to the log
    # file (or /dev/null if --printtoconsole was set without --debuglogfile,
    # which is unusual but legal).
    let stdoutPath = if config.printToConsole: "" else: derivedLogPath
    let stderrPath = stdoutPath
    daemonize(stdoutPath, stderrPath)
    # After daemonize, the parent has exited. We are the daemon.

  # 3) log redirect (foreground case + when daemonize already routed but we
  #    still want to track the path for SIGHUP reopen)
  if derivedLogPath.len > 0:
    # daemonize already dup2'd these FDs, but we still need to register the
    # path with the SIGHUP handler.
    if not config.daemon:
      # Foreground: actually open the file now.
      redirectLogToFile(derivedLogPath)
    else:
      # Daemon: stdio is already pointing at the log file via dup2, but
      # SIGHUP reopen needs the path.
      discard currentLogPath()  # touch lock-init
      redirectLogToFile(derivedLogPath)

  # 4) PID file
  try:
    writePidFile(config.pidFile)
  except OSError as e:
    echo "WARNING: failed to write PID file " & config.pidFile & ": " & e.msg

  # 5) debug categories
  if config.debugCategories.len > 0:
    let cats = parseDebugCategories(config.debugCategories)
    applyDebugCategories(cats)

proc main() =
  var (cmd, config, args) = parseArgs()

  # Check for --import-blocks before normal startup
  if config.importBlocks.len > 0:
    # Honour reindex wipe even on import path so a stale chainstate
    # doesn't poison the import.
    if config.reindex:
      applyReindex(config)
    runBlockImport(config)
    return

  case cmd
  of cmdStart:
    operationalSetup(config)
    setupSignalHandlers()
    # Signal readiness AFTER the initial setup but BEFORE the long-lived
    # event loop.  We can't easily wait for "first connect" without a
    # bigger refactor, so this is "the daemon is past startup and about to
    # enter the main loop" — sufficient for systemd-style supervision.
    if config.readyFd >= 0:
      signalReadyFd(config.readyFd)
    try:
      waitFor startNode(config)
    finally:
      # Belt-and-braces: ensure PID file is removed even on unhandled error
      # paths that don't go through the SIGINT/SIGTERM handler.
      removePidFile()

  of cmdHelp:
    showHelp()

  of cmdVersion:
    echo "nimrod v" & NimrodVersion

  else:
    # Run RPC command
    waitFor runCommand(cmd, config, args)

when isMainModule:
  main()
