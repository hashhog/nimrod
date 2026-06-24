## nimrod - Bitcoin full node in Nim
## Unified CLI with subcommands for node operation, RPC interaction, and wallet management

import std/[parseopt, os, strutils, json, posix, net, base64, sysrand, tables, monotimes, times, sets, options, algorithm]
import chronos
import chronicles

import ./primitives/[types, serialize]
import ./consensus/[params, validation]
import ./storage/[db, chainstate, snapshot, blockstore, pruner, undo]
import ./storage/indexes/[blockfilterindex, gcs, coinstatsindex, txospenderindex]
import ./network/[peer, peermanager, sync, messages, compact_blocks, asmap, netgroup]
import ./mempool/[mempool, persist, orphan]
import ./mining/fees
import ./wallet/manager
import ./rpc/server
import ./rpc/rpc_thread
import ./rpc/rest
import ./crypto/[secp256k1, hashing]
import ./perf/verify_pool
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
    dbcacheMiB*: int      ## --dbcache=<MiB>: UTXO cache budget in MiB (Core units).
                          ## 0 = use compiled defaults (2 GiB byte ceiling +
                          ## 200_000 IBD entry target). PERF-ONLY / consensus-neutral.
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
    coinstatsindex*: bool   ## --coinstatsindex: maintain the per-height UTXO
                            ## set statistics index (running MuHash3072 +
                            ## counts/amounts, folded forward on every block
                            ## connect and reversed on disconnect/reorg).
                            ## Mirrors Bitcoin Core's `-coinstatsindex`.
                            ## Required for `gettxoutsetinfo` to answer a
                            ## historical `hash_or_height`; without it that
                            ## form errors RPC -8 "Querying specific block
                            ## heights requires coinstatsindex" (Core parity).
    txospenderindex*: bool  ## --txospenderindex: maintain the spent-outpoint ->
                            ## spending-tx index (Bitcoin Core's
                            ## `-txospenderindex`, DEFAULT_TXOSPENDERINDEX{false}).
                            ## Folded forward on every block connect and erased on
                            ## disconnect/reorg. Required for the CONFIRMED-spend
                            ## path of `gettxspendingprevout`; without it that RPC
                            ## can answer only mempool spends and otherwise errors
                            ## "Mempool lacks a relevant spend, and
                            ## txospenderindex is unavailable." (Core parity).
    peerblockfilters*: bool ## --peerblockfilters: serve BIP-157 compact
                            ## filters to peers and advertise
                            ## NODE_COMPACT_FILTERS (1<<6 = 64) in our
                            ## version handshake.  Default OFF, matching
                            ## Core's `DEFAULT_PEERBLOCKFILTERS = false`
                            ## (net_processing.h:45).  Requires
                            ## `--blockfilterindex`: setting this flag
                            ## without the index is a hard startup error
                            ## (matches Core init.cpp:993-996 "Cannot set
                            ## -peerblockfilters without -blockfilterindex").
                            ## W121 G15 / FIX-71.
    asmapFile*: string      ## --asmap=<file>: ASMap binary file for ASN-keyed
                            ## eclipse-resistance bucketing.  Empty = disabled
                            ## (fallback to /16 / /32 groups).
                            ## Reference: bitcoin-core/src/init.cpp -asmap arg.
    proxy*: string          ## --proxy=host:port: SOCKS5 proxy for IPv4/IPv6
                            ## clearnet outbound connections (and .onion when
                            ## --onion is not set separately).  Mirrors
                            ## Bitcoin Core `-proxy=host:port`.  W117 FIX-56.
    onionProxy*: string     ## --onion=host:port: dedicated SOCKS5 proxy for
                            ## .onion outbound (typically the Tor SOCKS port,
                            ## 127.0.0.1:9050). When set, .onion peers use this
                            ## instead of the clearnet --proxy. Mirrors Core's
                            ## `-onion=host:port`.  W117 FIX-56.
    i2psam*: string         ## --i2psam=host:port: I2P SAM bridge endpoint for
                            ## .i2p outbound (default SAM port is 7656).
                            ## Mirrors Core's `-i2psam=host:port`.  W117 FIX-56.
    connectPeers*: seq[string] ## --connect=<ip:port> (repeatable): connect to
                            ## ONLY these peers and disable DNS-seed resolution
                            ## AND auto-outbound (addrman/diversity) dialing.
                            ## Mirrors Bitcoin Core `-connect` (which implies
                            ## `-dnsseed=0`) and clearbit's --connect branch.
                            ## Empty = normal DNS + auto-outbound behavior.
    noDnsSeed*: bool        ## --nodnsseed / --dnsseed=0: suppress DNS-seed
                            ## resolution independently of --connect.  Default
                            ## false (DNS seeding on).  Mirrors Core `-dnsseed`.
    cjdnsReachable*: bool   ## --cjdnsreachable: allow outbound connections to
                            ## CJDNS addresses (fc00::/8).  Default off — Core
                            ## requires the operator to opt-in because the host
                            ## must already have a CJDNS route.  Mirrors Core's
                            ## `-cjdnsreachable`.  W117 FIX-56.
    rpcTlsCert*: string     ## --rpc-tls-cert=<path>: PEM-encoded X.509
                            ## certificate served by the REST listener.
                            ## When set together with `--rpc-tls-key`, the
                            ## listener becomes HTTPS (TLS 1.2+).  Empty by
                            ## default — listener stays plaintext HTTP for
                            ## backward compatibility.  Required for clearnet
                            ## BIP-78 PayJoin per §Protocol.  W119 + FIX-64.
    rpcTlsKey*: string      ## --rpc-tls-key=<path>: PKCS#8 PEM private key
                            ## paired with `--rpc-tls-cert`.  Must be
                            ## unencrypted (BearSSL/chronos requirement).
                            ## Setting one without the other is a hard error
                            ## at startup — no silent downgrade.

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
    coinStatsIndex*: CoinStatsIndex       ## Per-height UTXO-set statistics
                                          ## index (running MuHash + counts).
                                          ## nil when --coinstatsindex is not
                                          ## set. Wired into RpcServer so
                                          ## gettxoutsetinfo can answer a
                                          ## historical hash_or_height and
                                          ## getindexinfo can report it.
    txoSpenderIndex*: TxoSpenderIndex     ## Spent-outpoint -> spending-tx index
                                          ## (Core's -txospenderindex). nil when
                                          ## --txospenderindex is not set. Wired
                                          ## into RpcServer so gettxspendingprevout
                                          ## can answer the CONFIRMED-spend path
                                          ## and getindexinfo can report it.
    restServer*: RestServer               ## Optional /rest/* HTTP server.
                                          ## nil when --rest is not set.
    restThread*: Thread[RestServer]       ## REST listener runs on its own
                                          ## OS thread — same rationale as
                                          ## the RPC thread (event-loop
                                          ## isolation from main-thread
                                          ## verifyScripts batches; see
                                          ## rpc_thread.nim).
    walletReconcileThread*: Thread[WalletManager]
                                          ## Background wallet history rescan
                                          ## (reconcileAllWalletsToTip) runs on
                                          ## its own OS thread so a full-chain
                                          ## scan (first restart after the
                                          ## wallet fix, or a seed-restore with
                                          ## lastSyncedHeight = -1) does NOT
                                          ## block RPC bind / P2P / sync on the
                                          ## boot path. Mirrors Core
                                          ## CWallet::AttachChain keeping RPC
                                          ## responsive during a rescan
                                          ## (getwalletinfo.scanning). MUST be
                                          ## held by NodeState for process
                                          ## lifetime — same `addr(t)` SIGSEGV
                                          ## trap the RPC/REST threads document.
    netGroupManager*: NetGroupManager     ## ASMap-aware network group manager.
                                          ## Loaded from config.asmapFile at
                                          ## startup; nil-replaced with an empty
                                          ## (non-asmap) manager when no file is
                                          ## given.  Wired into peerManager and
                                          ## the getpeerinfo RPC handler.
    lastAsmapHealthCheck*: int64          ## Unix timestamp of last ASMapHealthCheck.
                                          ## 0 = never run.  Checked every heartbeat;
                                          ## re-runs every 3600 s.

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
    dbcacheMiB: 0,        # 0 = use compiled cache defaults (default-preserving)
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
    blockfilterindex: false,
    coinstatsindex: false,    # Core parity: DEFAULT_COINSTATSINDEX = false
    peerblockfilters: false,  # Core parity: DEFAULT_PEERBLOCKFILTERS = false
    asmapFile: "",          # empty = ASMap disabled
    # W117 FIX-56 proxy flags (all default off)
    proxy: "",
    onionProxy: "",
    i2psam: "",
    connectPeers: @[],
    noDnsSeed: false,
    cjdnsReachable: false,
    # W119 + FIX-64 REST/TLS termination (default off — plaintext)
    rpcTlsCert: "",
    rpcTlsKey: ""
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
    of "dbcache":
      try:
        let v = parseInt(value)
        if v >= 0 and v <= 1048576:
          config.dbcacheMiB = v
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
    of "coinstatsindex":
      # Core's `-coinstatsindex` boolean: maintain the per-height UTXO-set
      # statistics index used to answer gettxoutsetinfo at a historical height.
      let v = value.toLowerAscii()
      if v in ["", "1", "true", "yes"]:
        config.coinstatsindex = true
      elif v in ["0", "false", "no"]:
        config.coinstatsindex = false
    of "txospenderindex":
      # Core's `-txospenderindex` boolean (DEFAULT_TXOSPENDERINDEX{false}):
      # maintain the spent-outpoint -> spending-tx index used by the
      # CONFIRMED-spend path of gettxspendingprevout.
      let v = value.toLowerAscii()
      if v in ["", "1", "true", "yes"]:
        config.txospenderindex = true
      elif v in ["0", "false", "no"]:
        config.txospenderindex = false
    of "peerblockfilters":
      # W121 G15 / FIX-71: serve BIP-157 compact filters to peers and
      # advertise NODE_COMPACT_FILTERS.  Default OFF (Core parity).
      config.peerblockfilters = value.toLowerAscii() in ["", "1", "true", "yes"]
    of "txindex":
      # Accepted for Core CLI parity; nimrod always maintains the tx index
      # (cfTxIndex).  No separate toggle — see the command-line handler.
      discard
    of "asmap":
      config.asmapFile = value
    of "proxy":
      # W117 FIX-56: SOCKS5 proxy for clearnet (and .onion fallback)
      config.proxy = value
    of "onion":
      # W117 FIX-56: dedicated Tor SOCKS5 proxy for .onion
      config.onionProxy = value
    of "i2psam":
      # W117 FIX-56: I2P SAM bridge endpoint for .i2p
      config.i2psam = value
    of "cjdnsreachable":
      config.cjdnsReachable = value.toLowerAscii() in ["", "1", "true", "yes"]
    of "connect":
      # Core/clearbit -connect=<ip:port> (repeatable in conf): pin to ONLY
      # these peers; disables DNS + auto-outbound.  `connect=0` clears.
      if value.len == 0 or value == "0":
        config.connectPeers = @[]
      else:
        config.connectPeers.add(value)
    of "nodnsseed":
      config.noDnsSeed = value.toLowerAscii() in ["", "1", "true", "yes"]
    of "dnsseed":
      config.noDnsSeed = value.toLowerAscii() in ["0", "false", "no"]
    of "rpc-tls-cert", "rpctlscert":
      # W119 + FIX-64: PEM-encoded X.509 cert for the REST listener.
      config.rpcTlsCert = value
    of "rpc-tls-key", "rpctlskey":
      # W119 + FIX-64: PKCS#8 PEM key paired with rpc-tls-cert.
      config.rpcTlsKey = value
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
  --dbcache=N            UTXO cache budget in MiB, Bitcoin Core units (default: 0 =
                         compiled default ~2 GiB ceiling + 200000 IBD entry target;
                         only raises the cache, never shrinks below the default)

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
  --coinstatsindex       Maintain the per-height UTXO-set statistics index
                         (running MuHash + counts/amounts). Required for
                         gettxoutsetinfo to answer a historical hash_or_height.
                         Mirrors Bitcoin Core -coinstatsindex.
  --peerblockfilters     Serve BIP-157 compact filters to peers and advertise
                         NODE_COMPACT_FILTERS in the version handshake.
                         Default off (Core parity). Requires
                         --blockfilterindex: setting this without the index
                         is a startup error.
  --asmap=FILE           Load an ASMap binary file for ASN-keyed eclipse-
                         resistance bucketing.  When loaded, outbound peer
                         diversity is measured by Autonomous System Number
                         rather than /16 prefix.  Mirrors Bitcoin Core
                         -asmap=<file>.  W115 FIX-50.
  --proxy=HOST:PORT      SOCKS5 proxy for clearnet (IPv4/IPv6) outbound and
                         .onion fallback.  Mirrors Bitcoin Core -proxy.
                         W117 FIX-56.
  --onion=HOST:PORT      Dedicated Tor SOCKS5 proxy for .onion outbound.
                         Stream isolation per circuit.  Mirrors Bitcoin Core
                         -onion.  W117 FIX-56.
  --i2psam=HOST:PORT     I2P SAM bridge endpoint for .i2p outbound (default
                         SAM port is 7656).  Mirrors Bitcoin Core -i2psam.
                         W117 FIX-56.
  --cjdnsreachable       Allow outbound to CJDNS addresses (fc00::/8).
                         Default off; the host must have a CJDNS route.
                         Mirrors Bitcoin Core -cjdnsreachable.  W117 FIX-56.
  --connect=IP:PORT      Connect to ONLY this peer (repeatable for multiple).
                         Disables DNS-seed resolution and auto-outbound
                         (addrman/diversity) dialing — the node talks to just
                         the pinned peer(s).  Bare IP uses the network default
                         port.  --connect=0 clears the list.  Mirrors Bitcoin
                         Core -connect (which implies -dnsseed=0).
  --nodnsseed            Suppress DNS-seed resolution (equivalently
                         --dnsseed=0), independently of --connect.  Mirrors
                         Bitcoin Core -dnsseed=0.
  --rpc-tls-cert=PATH    PEM-encoded X.509 cert for the REST listener.
                         Pair with --rpc-tls-key to enable HTTPS (TLS 1.2+).
                         Required for clearnet BIP-78 PayJoin.  W119 + FIX-64.
  --rpc-tls-key=PATH     PKCS#8 PEM private key paired with --rpc-tls-cert.
                         Must be unencrypted (BearSSL/chronos requirement).
                         Setting only one of the pair is a hard startup error
                         — no silent downgrade to plaintext.

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
      of "dbcache":
        try:
          let v = parseInt(p.val)
          if v < 0 or v > 1048576:
            echo "dbcache must be 0-1048576 MiB (0 = compiled default ~2 GiB)"
            quit(1)
          result.config.dbcacheMiB = v
        except ValueError:
          echo "Invalid dbcache: " & p.val
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
      of "coinstatsindex":
        # Bitcoin Core's `-coinstatsindex` boolean. Maintain the per-height
        # UTXO-set statistics index (running MuHash + counts/amounts) so
        # gettxoutsetinfo can answer a historical hash_or_height.
        let v = p.val.toLowerAscii()
        if v.len == 0 or v in ["1", "true", "yes"]:
          result.config.coinstatsindex = true
        elif v in ["0", "false", "no"]:
          result.config.coinstatsindex = false
        else:
          echo "Invalid --coinstatsindex value: " & p.val & " (use 1 / 0)"
          quit(1)
      of "txospenderindex":
        # Bitcoin Core's `-txospenderindex` boolean
        # (DEFAULT_TXOSPENDERINDEX{false}). Maintain the spent-outpoint ->
        # spending-tx index used by the CONFIRMED-spend path of
        # gettxspendingprevout.
        let v = p.val.toLowerAscii()
        if v.len == 0 or v in ["1", "true", "yes"]:
          result.config.txospenderindex = true
        elif v in ["0", "false", "no"]:
          result.config.txospenderindex = false
        else:
          echo "Invalid --txospenderindex value: " & p.val & " (use 1 / 0)"
          quit(1)
      of "peerblockfilters":
        # W121 G15 / FIX-71: --peerblockfilters — serve BIP-157 compact
        # filters and advertise NODE_COMPACT_FILTERS.  Default OFF.
        # Mirrors Bitcoin Core `-peerblockfilters`
        # (DEFAULT_PEERBLOCKFILTERS = false).
        let v = p.val.toLowerAscii()
        if v.len == 0 or v in ["1", "true", "yes"]:
          result.config.peerblockfilters = true
        elif v in ["0", "false", "no"]:
          result.config.peerblockfilters = false
        else:
          echo "Invalid --peerblockfilters value: " & p.val &
               " (use 1 / 0)"
          quit(1)
      of "asmap":
        result.config.asmapFile = p.val
      of "proxy":
        # W117 FIX-56: --proxy=host:port — SOCKS5 proxy for clearnet outbound
        # (and .onion when --onion is not separately configured).  Mirrors
        # Bitcoin Core's -proxy=host:port.  Empty value disables.
        result.config.proxy = p.val
      of "onion":
        # W117 FIX-56: --onion=host:port — dedicated Tor SOCKS5 proxy for
        # .onion outbound.  Stream isolation is enabled by default so each
        # .onion connect gets a fresh Tor circuit.  Mirrors Core's -onion.
        result.config.onionProxy = p.val
      of "i2psam":
        # W117 FIX-56: --i2psam=host:port — I2P SAM bridge endpoint for
        # .i2p outbound (default SAM port is 7656).  Mirrors Core's -i2psam.
        result.config.i2psam = p.val
      of "cjdnsreachable":
        # W117 FIX-56: --cjdnsreachable — opt-in flag that allows outbound
        # to CJDNS addresses (fc00::/8).  Default off — the host must have a
        # CJDNS route.  Mirrors Core's -cjdnsreachable.
        if p.val.len == 0:
          result.config.cjdnsReachable = true
        else:
          result.config.cjdnsReachable = p.val.toLowerAscii() in ["1", "true", "yes"]
      of "connect":
        # Core/clearbit -connect=<ip:port> (repeatable): pin to ONLY these
        # peers; disables DNS-seed resolution + auto-outbound fill.  Empty
        # value (`--connect=` alone, like Core's `-connect=0`) clears the list.
        if p.val.len == 0 or p.val == "0":
          result.config.connectPeers = @[]
        else:
          result.config.connectPeers.add(p.val)
      of "nodnsseed":
        # Core -dnsseed=0 / -nodnsseed: suppress DNS-seed resolution.
        if p.val.len == 0:
          result.config.noDnsSeed = true
        else:
          result.config.noDnsSeed = p.val.toLowerAscii() in ["1", "true", "yes"]
      of "dnsseed":
        # Core -dnsseed=<0|1>: --dnsseed=0 suppresses DNS seeding.
        result.config.noDnsSeed = p.val.toLowerAscii() in ["0", "false", "no"]
      of "rpc-tls-cert", "rpctlscert":
        # W119 + FIX-64: --rpc-tls-cert=<path> — PEM X.509 cert served by
        # the REST listener.  Pair with --rpc-tls-key to enable HTTPS.
        result.config.rpcTlsCert = p.val
      of "rpc-tls-key", "rpctlskey":
        # W119 + FIX-64: --rpc-tls-key=<path> — PKCS#8 PEM key paired with
        # --rpc-tls-cert.  Must be unencrypted (BearSSL requirement).
        result.config.rpcTlsKey = p.val
      of "txindex":
        # Bitcoin Core's `-txindex`.  nimrod maintains a transaction index
        # unconditionally (cfTxIndex is populated on every block connect — see
        # getTxIndex consumers in rpc/server.nim and rpc/rest.nim), so this
        # flag is accepted for CLI parity but does not toggle a separate index.
        # We tolerate `--txindex`, `--txindex=1` and `--txindex=0` without error
        # so Core-shaped launch lines (e.g. the coinstatsindex harness, which
        # passes `--coinstatsindex=1 --txindex=1`) start cleanly.
        discard
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
      blockAccepted = state.syncManager.processBlock(peer, msg.blk)
    except Defect as e:
      # Log but don't crash — the block will be retried
      let ht = state.syncManager.chainTipHeight
      echo "DEFECT in processBlock (chainTip=", ht, "): ", e.msg
      when compileOption("stackTrace"):
        echo getStackTrace(e)
    if blockAccepted:
      {.gcsafe.}:
        # Reorg-drop fix (Part 2): when processBlock promoted a heavier competing
        # fork via the side-branch path, the active tip switched to that branch.
        # The mempool refresh then differs from a plain extension: FIRST refill
        # the disconnected old-chain non-coinbase txs (Pattern B —
        # MaybeUpdateMempoolForReorg via the disconnect pool), THEN drop the txs
        # confirmed by EVERY newly-connected fork block (not just msg.blk, which
        # is only the new tip).  Mirrors the submitblock reorg refresh in
        # rpc/server.nim.  pendingReorgConnectedBlocks is non-empty ONLY on a
        # reorg; the common (extension) path falls through to the single
        # removeForBlock below.
        let reorgConnected = state.syncManager.pendingReorgConnectedBlocks
        if reorgConnected.len > 0:
          let reorgDisconnected = state.syncManager.pendingReorgDisconnectedTxs
          try:
            if reorgDisconnected.len > 0:
              discard state.mempool.blockDisconnected(reorgDisconnected, state.crypto)
          except CatchableError as e:
            warn "P2P reorg mempool refill failed", error = e.msg
          except Exception as e:
            warn "P2P reorg mempool refill failed", error = e.msg
          for connected in reorgConnected:
            state.mempool.removeForBlock(connected)
            if state.orphanPool != nil:
              discard state.orphanPool.removeForBlock(connected)
          state.syncManager.pendingReorgConnectedBlocks.setLen(0)
          state.syncManager.pendingReorgDisconnectedTxs.setLen(0)
        else:
          # Remove confirmed transactions from mempool (plain extension).
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
              # G27: store both txid and wtxid so the rejection filter works
              # regardless of whether a peer re-announces via invTx or invWtx.
              if state.recentlyRejected.len < 50_000:
                state.recentlyRejected.incl(child.tx.txid())
              if state.recentlyRejected.len < 50_000:
                state.recentlyRejected.incl(child.tx.wtxid())
    elif missingInputs:
      # Hold the orphan briefly in case the parent arrives.  Capped pool
      # mirrors Core (100 txs / 100KB / peer cap).  Note we do NOT add to
      # recentlyRejected here — that would block re-requesting from a
      # subsequent peer once we see the parent.
      if state.orphanPool != nil:
        discard state.orphanPool.addOrphan(msg.tx, orphanPeer)
    else:
      # Track rejection to avoid re-requesting.
      # G27: store both txid and wtxid so that a segwit tx rejected under its
      # txid is also filtered when a peer later announces it by wtxid
      # (invWtx), and vice versa.
      let wtxid = msg.tx.wtxid()
      if state.recentlyRejected.len < 50_000:
        state.recentlyRejected.incl(txid)
      if state.recentlyRejected.len < 50_000 and wtxid != txid:
        state.recentlyRejected.incl(wtxid)

  of mkInv:
    # Request blocks we don't have
    var blockInvs: seq[InvVector]
    var txInvs: seq[InvVector]
    # During IBD, do NOT solicit loose mempool transactions.  Each peer
    # announces hundreds of mempool txs per `inv`; firing a `getdata` for
    # every one floods the peer's send buffer, and that backpressure stalls
    # the peer's getdata FIFO *before* it reaches the block we actually
    # need (which is queued behind the tx flood) — block download then
    # never makes progress.  Mirrors Bitcoin Core net_processing.cpp, whose
    # INV handler only requests txs inside `if (!IsInitialBlockDownload())`.
    # Block invs are still processed below regardless of IBD state.
    let inIBD = state.syncManager != nil and
                state.syncManager.isInitialBlockDownload()
    for item in msg.invItems:
      if item.invType == invBlock or item.invType == invWitnessBlock:
        # Request as witness block for segwit support
        blockInvs.add(InvVector(invType: invWitnessBlock, hash: item.hash))
      elif item.invType == invTx or item.invType == invWitnessTx or
           item.invType == invWtx:
        # Skip all tx-announcement handling while still catching up — see
        # the `inIBD` comment above.
        if inIBD:
          continue
        # BIP-339 per-peer inv type filter.
        # wtxid-relay peers send invWtx (MSG_WTX=5); ignore invTx from them.
        # Legacy peers send invTx (MSG_TX=1); ignore invWtx from them.
        # invWitnessTx (0x40000001) is a getdata flag, not a valid inv type,
        # but tolerate it from legacy peers as invTx equivalent.
        if peer.wtxidRelay and item.invType == invTx:
          continue  # wtxid-relay peer should not send invTx; skip it
        if not peer.wtxidRelay and item.invType == invWtx:
          continue  # legacy peer should not send invWtx; skip it

        # G27: use item.hash directly as the rejection-filter key.
        # For invTx items (txid), recentlyRejected stores the txid.
        # For invWtx items (wtxid), recentlyRejected stores the wtxid.
        # Both are stored on rejection (see mkTx handler), so this lookup
        # is correct regardless of which namespace the peer uses.
        let lookupHash = TxId(item.hash)
        if not state.mempool.contains(lookupHash) and
            lookupHash notin state.recentlyRejected:
          # Request using MSG_WITNESS_TX getdata flag so we get witness data.
          txInvs.add(InvVector(invType: invWitnessTx, hash: item.hash))
    if blockInvs.len > 0:
      asyncSpawn spawnSafe(peer.sendGetData(blockInvs))
    if txInvs.len > 0:
      # G5: cap outgoing getdata at MAX_GETDATA_SZ=1000 items per message.
      # Core: net_processing.cpp:6207 flushes vGetData when it reaches 1000.
      # A peer may send up to MAX_INV_SZ=50000 items in a single inv; without
      # batching we would send a single getdata with up to 50000 items.
      var i = 0
      while i < txInvs.len:
        let batch = txInvs[i ..< min(i + MaxGetDataSize, txInvs.len)]
        asyncSpawn spawnSafe(peer.sendGetData(batch))
        i += MaxGetDataSize

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
      elif item.invType == invCmpctBlock:
        # getdata(MSG_CMPCTBLOCK): serve a compact block if the requested block
        # is within MAX_CMPCTBLOCK_DEPTH (5) of the chain tip; otherwise fall
        # back to serving the full block.
        # Reference: Bitcoin Core net_processing.cpp:2466
        #   if (can_direct_fetch && pindex->nHeight >= tip->nHeight - MAX_CMPCTBLOCK_DEPTH)
        let blockOpt = state.chainState.db.getBlock(BlockHash(item.hash))
        if blockOpt.isSome:
          let blk = blockOpt.get()
          let idxOpt = state.chainState.db.getBlockIndex(BlockHash(item.hash))
          let tipHeight = state.chainState.bestHeight
          let blockHeight = if idxOpt.isSome: idxOpt.get().height else: tipHeight
          if cmpctBlockDepthOk(blockHeight, tipHeight):
            # Within depth limit — send compact block
            let nonce = urandom(8)
            var nonceVal: uint64
            for i in 0 ..< 8: nonceVal = nonceVal or (uint64(nonce[i]) shl (i * 8))
            let cb = newCompactBlock(blk, nonceVal)
            let cmpctMsg = newCmpctBlockMsg(cb)
            try:
              await peer.sendMessage(cmpctMsg)
              servedBlocks.inc
            except CatchableError as e:
              debug "failed to serve cmpctblock", peer = $peer, error = e.msg
          else:
            # Too deep — fall back to full block
            debug "cmpctblock depth exceeded, serving full block",
                  peer = $peer, blockHeight = blockHeight, tipHeight = tipHeight
            let blkMsg = newBlockMsg(blk)
            try:
              await peer.sendMessage(blkMsg)
              servedBlocks.inc
            except CatchableError as e:
              debug "failed to serve block (cmpct fallback)", peer = $peer, error = e.msg
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
        # Unknown / unsupported inv type (filtered-block, etc.)
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
        for txid, entry in state.mempool.entries:
          # G20 (BIP-339): wtxid-relay peers get invWtx with the wtxid;
          # legacy peers get invTx with the txid.
          let (itemType, itemHash) =
            if peer.wtxidRelay:
              (invWtx, array[32, byte](entry.wtxid))
            else:
              (invTx, array[32, byte](txid))
          batch.add(InvVector(invType: itemType, hash: itemHash))
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
    # BIP-331: peer delivered an ancestor package.  Pass the full sequence to
    # acceptPackage so that CPFP fee-rate aggregation is applied (a parent with
    # a below-minimum individual fee rate can be accepted when the child's fee
    # covers the shortfall).  Calling acceptTransaction per-tx would break CPFP
    # because each tx is evaluated in isolation without the package fee rate.
    # Reference: Bitcoin Core net_processing.cpp ProcessPackage / acceptPackage.
    if state.mempool == nil:
      trace "pkgtxns before mempool init", peer = $peer
    else:
      let txns = msg.pkgTxns.transactions
      var pkgResult: PackageResult
      {.gcsafe.}:
        try:
          pkgResult = state.mempool.acceptPackage(txns, state.crypto,
                                                  usePackageFeerates = true)
        except CatchableError as e:
          debug "pkgtxns acceptPackage exception", peer = $peer, error = e.msg
        except Exception as e:
          debug "pkgtxns acceptPackage fatal", peer = $peer, error = e.msg
      var accepted = 0
      for txr in pkgResult.txResults:
        if txr.allowed:
          inc accepted
        else:
          debug "pkgtxns tx rejected", peer = $peer,
                txid = $txr.txid, reason = txr.error
      debug "processed pkgtxns",
            peer = $peer, total = txns.len,
            accepted = accepted, pkgValid = pkgResult.valid

  # BIP-157 compact block filter serving
  # Reference: bitcoin-core/src/net_processing.cpp:ProcessGetCFilters,
  #            ProcessGetCFHeaders, ProcessGetCFCheckPt.
  # Gates: NODE_COMPACT_FILTERS must be in our services, index must be enabled.
  # Protocol-violation paths (unsupported filter type / unknown stop hash /
  # inverted range / oversized range) MUST disconnect — FIX-78 (W121 G20).
  of mkGetCFilters:
    # Serve individual compact filters for a range of blocks.
    # Wire: getcfilters → one cfilter per block in [startHeight..stopBlock]
    # Limit: MAX_GETCFILTERS_SIZE = 1000 blocks per request.
    if state.blockFilterIndex == nil or not state.blockFilterIndex.enabled:
      debug "ignoring getcfilters: blockfilterindex not enabled", peer = $peer
    else:
      let req = msg.getCFilters
      let stopBlockHash = BlockHash(req.stopHash)
      let stopIdxOpt = state.chainState.db.getBlockIndex(stopBlockHash)
      let stopHeight =
        if stopIdxOpt.isSome: stopIdxOpt.get().height else: 0'i32
      let startHeight = int32(req.startHeight)
      let violation = validateGetCFiltersRequest(
        req.filterType, startHeight, stopHeight,
        stopFound = stopIdxOpt.isSome,
        maxRange = CFiltersMaxRange)
      if violation != cfrvNone:
        # Core: node.fDisconnect = true on every violation path —
        # bitcoin-core/src/net_processing.cpp:3271-3304 (PrepareBlockFilterRequest).
        await disconnectOnBadFilterRequest(peer, violation, "getcfilters")
        return
      for h in startHeight .. stopHeight:
        let hashOpt = state.chainState.db.getBlockHashByHeight(h)
        if hashOpt.isNone: break
        let bh = hashOpt.get()
        let fOpt = state.blockFilterIndex.getFilter(h, bh)
        if fOpt.isNone: break
        try:
          await peer.sendMessage(
            newCFilter(req.filterType, array[32, byte](bh),
                       getEncodedFilter(fOpt.get())))
        except CatchableError as e:
          debug "getcfilters: send failed", peer = $peer, error = e.msg
          break

  of mkGetCFHeaders:
    # Serve compact filter headers for a range of blocks.
    # Wire: getcfheaders → one cfheaders with hashes for [startHeight..stopBlock]
    # Limit: MAX_GETCFHEADERS_SIZE = 2000 blocks per request.
    if state.blockFilterIndex == nil or not state.blockFilterIndex.enabled:
      debug "ignoring getcfheaders: blockfilterindex not enabled", peer = $peer
    else:
      let req = msg.getCFHeaders
      let stopBlockHash = BlockHash(req.stopHash)
      let stopIdxOpt = state.chainState.db.getBlockIndex(stopBlockHash)
      let stopHeight =
        if stopIdxOpt.isSome: stopIdxOpt.get().height else: 0'i32
      let startHeight = int32(req.startHeight)
      let violation = validateGetCFiltersRequest(
        req.filterType, startHeight, stopHeight,
        stopFound = stopIdxOpt.isSome,
        maxRange = CFHeadersMaxRange)
      if violation != cfrvNone:
        # Core: node.fDisconnect = true on every violation path —
        # bitcoin-core/src/net_processing.cpp:3271-3304 (PrepareBlockFilterRequest).
        await disconnectOnBadFilterRequest(peer, violation, "getcfheaders")
        return
      # Fetch prevFilterHeader (filter header at startHeight - 1)
      var prevFilterHeader: array[32, byte]
      if startHeight > 0:
        let prevHOpt = state.blockFilterIndex.getFilterHeader(startHeight - 1)
        if prevHOpt.isSome:
          prevFilterHeader = prevHOpt.get()
      # Fetch per-block filter hashes
      var filterHashes: seq[array[32, byte]]
      var ok = true
      for h in startHeight .. stopHeight:
        let fhOpt = state.blockFilterIndex.getFilterHash(h)
        if fhOpt.isNone: ok = false; break
        filterHashes.add(fhOpt.get())
      if ok:
        try:
          await peer.sendMessage(
            newCFHeaders(req.filterType, array[32, byte](stopBlockHash),
                         prevFilterHeader, filterHashes))
        except CatchableError as e:
          debug "getcfheaders: send failed", peer = $peer, error = e.msg

  of mkGetCFCheckPt:
    # Serve compact filter checkpoints (headers at every 1000-block interval).
    # Wire: getcfcheckpt → one cfcheckpt with filter headers at CFCHECKPT_INTERVAL
    # heights up to and including stopBlock.
    # Reference: bitcoin-core/src/net_processing.cpp:ProcessGetCFCheckPt
    if state.blockFilterIndex == nil or not state.blockFilterIndex.enabled:
      debug "ignoring getcfcheckpt: blockfilterindex not enabled", peer = $peer
    else:
      let req = msg.getCFCheckPt
      let stopBlockHash = BlockHash(req.stopHash)
      let stopIdxOpt = state.chainState.db.getBlockIndex(stopBlockHash)
      let violation = validateGetCFCheckPtRequest(
        req.filterType, stopFound = stopIdxOpt.isSome)
      if violation != cfrvNone:
        # Core ProcessGetCFCheckPt passes max_height_diff = uint32.max, so the
        # range paths can't trip here; only filter-type + stop-hash apply.
        # bitcoin-core/src/net_processing.cpp:3397-3401.
        await disconnectOnBadFilterRequest(peer, violation, "getcfcheckpt")
        return
      let stopHeight = stopIdxOpt.get().height
      var headers: seq[array[32, byte]]
      let nCheckpoints = stopHeight div CFCheckPtInterval
      var ok = true
      for i in 1 .. nCheckpoints:
        let cpHeight = int32(i) * CFCheckPtInterval
        let cpHashOpt = state.chainState.db.getBlockHashByHeight(cpHeight)
        if cpHashOpt.isNone: ok = false; break
        let cpFhOpt = state.blockFilterIndex.getFilterHeader(cpHeight)
        if cpFhOpt.isNone: ok = false; break
        headers.add(cpFhOpt.get())
      if ok:
        try:
          await peer.sendMessage(
            newCFCheckPt(req.filterType, array[32, byte](stopBlockHash),
                         headers))
        except CatchableError as e:
          debug "getcfcheckpt: send failed", peer = $peer, error = e.msg

  # BIP-157 response messages (cfilter/cfheaders/cfcheckpt) — currently
  # received only when nimrod acts as a light-client requesting filters.
  # No handler needed on the server-path; silently drop for now.
  of mkCFilter, mkCFHeaders, mkCFCheckPt:
    trace "received BIP-157 filter response", peer = $peer, kind = $msg.kind

  # BIP-37 bloom filter messages — BIP-111 requires disconnect when NODE_BLOOM is
  # not advertised.  Nimrod never advertises NODE_BLOOM (W110 BUG-01 / FIX-35),
  # so all three always trigger disconnect.
  # Reference: bitcoin-core/src/net_processing.cpp:4963-5033
  of mkFilterLoad:
    warn "filterload received despite not offering bloom services — disconnecting",
         peer = $peer
    await peer.disconnect("filterload received — NODE_BLOOM not advertised (BIP-111)")

  of mkFilterAdd:
    warn "filteradd received despite not offering bloom services — disconnecting",
         peer = $peer
    await peer.disconnect("filteradd received — NODE_BLOOM not advertised (BIP-111)")

  of mkFilterClear:
    warn "filterclear received despite not offering bloom services — disconnecting",
         peer = $peer
    await peer.disconnect("filterclear received — NODE_BLOOM not advertised (BIP-111)")

  # merkleblock — server→client message; we would not normally receive one.
  # Log and drop; do not disconnect.
  of mkMerkleBlock:
    warn "unexpected merkleblock received — dropping", peer = $peer

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

      # Final wallet flush. Save-on-mutation already keeps every loaded
      # wallet's snapshot current; this is the belt-and-suspenders pass so a
      # clean shutdown is guaranteed durable too. DATA-LOSS FIX wa0fq5wtk.
      if globalNodeState.rpcServer != nil and
         globalNodeState.rpcServer.walletManager != nil:
        info "flushing wallets"
        try: globalNodeState.rpcServer.walletManager.persistAllWallets()
        except CatchableError: discard

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
  # --dbcache override (no-op when 0); set on the instance so the startIBD
  # below inherits the raised IBD entry-count target.
  cs.setDbCache(config.dbcacheMiB)

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

  # Shared crypto engine for script verification across the entire reindex.
  # Held in scope so secp256k1 context construction (which is non-trivial)
  # happens once per --import invocation, not once per block.
  let importCrypto = newCryptoEngine()

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

      # Route through canonical acceptBlock envelope (W143 BUG-3 / W145 BUG-1
      # fix). Previously this path called `checkBlock` + `connectBlockIBD`
      # only, bypassing contextualCheckBlockHeader (nBits, MTP, BIP-94),
      # validateBlock (BIP-34, weight cap, sigops, coinbase value, witness
      # commitment, IsFinalTx), checkBip30 (CVE-2012-1909), CVE-2018-17144
      # duplicate-input check, and script verification — every contextual
      # consensus check. A hostile blocks.dat could advance the chain with
      # wrong-nBits / over-subsidy / over-weight blocks. Core's reindex
      # funnels through ProcessNewBlock → AcceptBlock → ContextualCheckBlock
      # → ConnectBlock; this matches.
      let connectResult = acceptAndConnectBlock(cs, blk, frameHeight,
                                                bsReindex, importCrypto,
                                                forceIbdConnect = true)
      if not connectResult.isOk:
        echo "Block accept/connect failed at height " & $frameHeight & ": " & connectResult.error
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

      # Route through canonical acceptBlock envelope (W143 BUG-3 / W145 BUG-1
      # fix; see stdin-import path above for full rationale).
      let connectResult = acceptAndConnectBlock(cs, blk, height,
                                                bsReindex, importCrypto,
                                                forceIbdConnect = true)
      if not connectResult.isOk:
        echo "Block accept/connect failed at height " & $height & ": " & connectResult.error
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

proc walletReconcileThreadMain(wm: WalletManager) {.thread.} =
  ## Thread entry point for the deferred startup wallet history rescan.
  ##
  ## reconcileAllWalletsToTip walks the gap [lastSyncedHeight+1 .. tip] for
  ## every loaded wallet, rebuilding its in-memory tx/UTXO history (DATA-LOSS
  ## FIX wa0fq5wtk). On a wallet whose locator is reset to -1 (the first
  ## restart after the wallet fix deploys, or a seed-restored wallet) that gap
  ## is the WHOLE chain 0..tip — ~950k blocks on mainnet. It used to run
  ## synchronously on the boot path BEFORE startRpcThread / the P2P listener /
  ## the sync loop, so the node looked DOWN for many minutes (RPC refused) until
  ## the scan finished — a restart-wedge (regression from the wallet-recovery
  ## fix). Bitcoin Core keeps RPC responsive while the wallet rescans
  ## (CWallet::AttachChain → getwalletinfo.scanning); we mirror that by running
  ## the rescan on this dedicated OS thread, started AFTER the RPC thread and
  ## P2P listener are up. The recovery behaviour is unchanged — history is still
  ## fully rebuilt and persisted — it just no longer blocks boot.
  ##
  ## scanBlockForWallet is a synchronous, CPU- and DB-bound loop, so this is a
  ## plain OS thread (like startRpcThread / restThreadMain), NOT an asyncSpawn:
  ## a CPU-bound scan on the main chronos loop would stall the heartbeat and any
  ## main-loop I/O. WalletManager takes its own walletsLock around every
  ## load/persist (manager.nim), and the RPC thread already shares this same
  ## `wm` ref concurrently, so running the locked reconcile here adds no new
  ## sharing hazard. The `{.gcsafe.}:` block mirrors rpcThreadMain.
  {.gcsafe.}:
    try:
      wm.reconcileAllWalletsToTip()
      info "background wallet reconcile complete"
    except CatchableError as e:
      warn "background wallet reconcile failed", error = e.msg
    except Exception as e:
      warn "background wallet reconcile failed", error = e.msg

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

  # BIP-157 W121 G15 / FIX-71: latch the NODE_COMPACT_FILTERS advertisement
  # gate.  Refuse to start if --peerblockfilters is set without
  # --blockfilterindex (mirrors Core init.cpp:993-996:
  # `InitError("Cannot set -peerblockfilters without -blockfilterindex.")`).
  # The bit is only advertised when both knobs are on; otherwise stays off.
  if config.peerblockfilters and not config.blockfilterindex:
    error "cannot set --peerblockfilters without --blockfilterindex"
    echo "Error: --peerblockfilters requires --blockfilterindex"
    quit(1)
  setCompactFiltersAdvertise(config.peerblockfilters and config.blockfilterindex)

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

  # 1a. Pre-warm the secp256k1 verify context and spin up the static parallel
  # script-verification worker pool (W167). initVerifyPool() calls
  # initSecp256k1() on THIS (main) thread before any worker can touch the
  # global context, closing the lazy-init TOCTOU race, then spawns the bounded
  # pool sized from --verify-threads (0 = auto = countProcessors()-1, clamped
  # to Core's MAX_SCRIPTCHECK_THREADS=15). verifyScripts auto-dispatches to the
  # pool once it is up. Must run before IBD / any acceptBlock call.
  let verifyWorkers = clampWorkers(config.numVerifyWorkers)
  info "initializing parallel script-verify pool",
    workers = verifyWorkers, requested = config.numVerifyWorkers
  initVerifyPool(config.numVerifyWorkers)

  # 2. Open database and chainstate
  info "opening database", path = networkDir / "chainstate"
  state.chainState = newChainState(networkDir / "chainstate", params)
  if config.ibdFlushInterval > 0:
    state.chainState.ibdDiskFlushInterval = config.ibdFlushInterval
  # --dbcache override (no-op when 0); set once on the single ChainState
  # instance the daemon shares, so the SyncManager and RPC startIBD call
  # sites inherit the raised byte ceiling + IBD entry target without each
  # needing `config` plumbed through.
  state.chainState.setDbCache(config.dbcacheMiB)

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
  # BUG-1 fix (W114 FIX-47): wire feeEstimator into mempool so that
  # acceptTransactionWithArgs calls trackTransaction on every successful accept.
  state.mempool.feeEstimator = state.feeEstimator

  # 5. Initialize peer manager
  info "initializing peer manager"
  # 5a. Load ASMap (W115 FIX-50): if --asmap=<file> was given, load the
  # binary trie and validate it.  On any failure loadAsmap returns an empty
  # seq and we fall back to /16 / /32 bucketing silently (Core behaviour).
  if config.asmapFile.len > 0:
    let asmapData = loadAsmap(config.asmapFile)
    state.netGroupManager = newNetGroupManager(asmapData)
    if state.netGroupManager.usingAsmap:
      info "ASMap loaded", file = config.asmapFile,
           version = state.netGroupManager.getAsmapVersionHex()
    else:
      warn "ASMap load failed, using /16 bucketing", file = config.asmapFile
  else:
    state.netGroupManager = newNetGroupManager()  # no asmap

  # FIX-51 (W115 G27): pass state.netGroupManager into PeerManager so that
  # outbound diversity checks (hasNetGroupCollision) and bucket-group storage
  # use ASN-keyed groups when an asmap file is loaded.
  # Reference: bitcoin-core/src/net.cpp CConnman constructor — m_netgroupman ref.
  state.peerManager = newPeerManager(
    params,
    maxOutFullRelay = config.maxConnections div 16,
    maxIn = config.maxConnections - config.maxConnections div 16,
    dataDir = networkDir,
    netGroupMgr = state.netGroupManager)
  state.peerManager.updateHeight(state.chainState.bestHeight)
  state.peerManager.setMessageCallback(messageCallback(state))

  # 5c. W117 BUG-3 FIX (FIX-56): wire the dead-helper src/network/proxy.nim
  # subsystems (SOCKS5 / Tor control / I2P SAM / ProxyManager) into the
  # outbound connect path based on --proxy / --onion / --i2psam /
  # --cjdnsreachable.
  # Reference: bitcoin-core/src/init.cpp AppInitMain calls SetProxy() and
  # SetReachable() from these arguments.
  proc parseHostPort(spec: string): Option[tuple[host: string, port: uint16]] =
    let colon = spec.rfind(':')
    if colon <= 0 or colon == spec.high:
      return none(tuple[host: string, port: uint16])
    let host = spec[0 ..< colon]
    try:
      let portVal = parseInt(spec[colon + 1 .. ^1])
      if portVal < 1 or portVal > 65535:
        return none(tuple[host: string, port: uint16])
      return some((host: host, port: uint16(portVal)))
    except ValueError:
      return none(tuple[host: string, port: uint16])

  if config.proxy.len > 0:
    let parsed = parseHostPort(config.proxy)
    if parsed.isSome:
      let hp = parsed.get()
      state.peerManager.configureProxy(hp.host, hp.port)
    else:
      warn "invalid --proxy value, expected host:port", value = config.proxy
  if config.onionProxy.len > 0:
    let parsed = parseHostPort(config.onionProxy)
    if parsed.isSome:
      let hp = parsed.get()
      state.peerManager.configureOnionProxy(hp.host, hp.port,
                                            randomizeCredentials = true)
    else:
      warn "invalid --onion value, expected host:port", value = config.onionProxy
  if config.i2psam.len > 0:
    let parsed = parseHostPort(config.i2psam)
    if parsed.isSome:
      let hp = parsed.get()
      let keyFile = networkDir / "i2p_private.key"
      state.peerManager.configureI2PSam(hp.host, hp.port,
                                        privateKeyFile = keyFile,
                                        transient = false)
    else:
      warn "invalid --i2psam value, expected host:port", value = config.i2psam
  if config.cjdnsReachable:
    state.peerManager.setCjdnsReachable(true)
    info "CJDNS outbound enabled"

  # -connect / -nodnsseed peer pinning (Core/clearbit semantics).  When
  # --connect is set the peer manager connects to ONLY these peers and skips
  # DNS-seed resolution + auto-outbound fill (handled in peermanager.nim:
  # startOutboundConnections / maintainConnections / resolveDnsSeeds).
  # Reference: bitcoin-core/src/init.cpp -connect (implies -dnsseed=0);
  # clearbit peer.zig:7009/7050.
  if config.noDnsSeed:
    state.peerManager.dnsSeedEnabled = false
    info "DNS seeding disabled (--nodnsseed / --dnsseed=0)"
  for spec in config.connectPeers:
    let parsed = parseHostPort(spec)
    if parsed.isSome:
      let hp = parsed.get()
      state.peerManager.connectPeers.add((host: hp.host, port: hp.port))
    elif spec.len > 0 and ':' notin spec:
      # Bare IP with no port: default to the chain's P2P port (Core parity —
      # `-connect=1.2.3.4` uses the network default port).
      state.peerManager.connectPeers.add((host: spec, port: params.defaultPort))
    else:
      warn "invalid --connect value, expected ip:port", value = spec
  if state.peerManager.connectPeers.len > 0:
    info "connect mode: pinned to fixed peers; DNS + auto-outbound disabled",
         peers = state.peerManager.connectPeers.len

  # 5b. Optional BIP-157 basic block-filter index.  Created BEFORE the sync
  # manager so we can pass it down — the SyncManager fans every successful
  # connectBlock out to the filter index when populated.  Reference:
  # bitcoin-core/src/index/base.cpp::BaseIndex::ConnectBlock.
  #
  # When --blockfilterindex is OFF the field stays nil and the REST endpoints
  # /rest/blockfilter[headers] return "Index is not enabled for filtertype
  # basic" (Core parity).
  if config.blockfilterindex:
    info "initializing blockfilterindex (basic)"
    state.blockFilterIndex = newBlockFilterIndex(
      state.chainState.db.db, networkDir, bftBasic, enabled = true)
  else:
    state.blockFilterIndex = nil

  # 5b'. Optional per-height UTXO-set statistics index (coinstatsindex).
  # Created BEFORE the sync manager so connectBlock fan-outs can maintain it,
  # and BEFORE the shared disconnect hook is installed (so the hook can see it).
  # Mirrors bitcoin-core/src/index/coinstatsindex.cpp.  When OFF the field
  # stays nil and gettxoutsetinfo at a non-tip hash_or_height errors -8 (Core
  # parity), while the @tip path is unchanged.
  if config.coinstatsindex:
    info "initializing coinstatsindex"
    state.coinStatsIndex = newCoinStatsIndex(
      state.chainState.db.db, params, enabled = true)
  else:
    state.coinStatsIndex = nil

  # txospenderindex (Core's -txospenderindex, default off). Spent-outpoint ->
  # spending-tx index backing the CONFIRMED-spend path of gettxspendingprevout.
  if config.txospenderindex:
    info "initializing txospenderindex"
    state.txoSpenderIndex = newTxoSpenderIndex(
      state.chainState.db.db, enabled = true)
  else:
    state.txoSpenderIndex = nil

  # Shared chainstate disconnect hook: when the chainstate disconnects a block
  # (legacy disconnectBlock or Pattern-D handleReorg) fan the rollback out to
  # BOTH optional indexes symmetrically.  The hook runs AFTER the chainstate
  # batch commits, so the indexes never observe an un-committed state.  Index
  # errors are swallowed (each index's removeBlock catches) so a failed index
  # rollback never corrupts the chainstate disconnect.  The hook only carries
  # (blockHash, prevHash, height); the coinstatsindex additionally needs the
  # block body + undo to reverse its MuHash, so we re-read both from storage by
  # hash here (same pattern as the IBD backfill below).  Mirrors
  # bitcoin-core's BaseIndex::BlockDisconnected fan-out.
  if state.blockFilterIndex != nil or state.coinStatsIndex != nil or
     state.txoSpenderIndex != nil:
    let filterIdx = state.blockFilterIndex
    let coinIdx = state.coinStatsIndex
    let txoIdx = state.txoSpenderIndex
    let csForHook = state.chainState
    let paramsForHook = params
    state.chainState.disconnectHook = proc(blockHash: BlockHash,
                                           prevHash: BlockHash,
                                           height: int32) {.raises: [].} =
      if filterIdx != nil:
        try:
          discard filterIdx.removeBlock(blockHash, prevHash, height)
        except CatchableError as e:
          warn "blockfilterindex: disconnectHook removeBlock raised, continuing",
               height = height, hash = $blockHash, error = e.msg
        except Exception as e:
          warn "blockfilterindex: disconnectHook removeBlock raised non-Catchable, continuing",
               height = height, hash = $blockHash, error = e.msg
      if coinIdx != nil:
        try:
          # Reverse the coinstatsindex MuHash for this block.  Re-read the
          # block body + its per-block undo by hash (the hook signature does
          # not carry them).  If either is unavailable the index logs + no-ops
          # (it cannot reverse without undo) — safe for the chainstate.
          let blkOpt = csForHook.db.getBlock(blockHash)
          if blkOpt.isSome:
            let blk = blkOpt.get()
            var blockUndo = chainstate.BlockUndo()
            let idxOpt = csForHook.db.getBlockIndex(blockHash)
            if idxOpt.isSome:
              let bidx = idxOpt.get()
              if bidx.undoPos.fileNum >= 0 and bidx.undoPos.pos >= 0:
                let (loaded, ok) = csForHook.undoMgr.readBlockUndo(
                  bidx.undoPos, prevHash, paramsForHook)
                if ok:
                  blockUndo = loaded
            discard coinIdx.removeBlock(blk, blockHash, prevHash, height, blockUndo)
          else:
            warn "coinstatsindex: disconnectHook could not read block body, skipping rollback",
                 height = height, hash = $blockHash
        except CatchableError as e:
          warn "coinstatsindex: disconnectHook removeBlock raised, continuing",
               height = height, hash = $blockHash, error = e.msg
        except Exception as e:
          warn "coinstatsindex: disconnectHook removeBlock raised non-Catchable, continuing",
               height = height, hash = $blockHash, error = e.msg
      if txoIdx != nil:
        try:
          # Erase the txospenderindex entries for this disconnected block by
          # RE-DERIVING its spend keys from the block's OWN inputs (no undo data
          # needed).  This single unified hook fires per disconnected block on
          # BOTH the invalidateblock path (disconnectBlock) AND the live reorg
          # path (handleReorg), disconnect-BEFORE-connect — so a reorg that
          # spends the same outpoint with a different tx on the new branch
          # erases the old branch's entry before the new branch's connect
          # re-writes it.  Re-read the block body by hash (the hook signature
          # does not carry it).  Mirrors Core CustomRemove(BuildSpenderPositions).
          let blkOpt = csForHook.db.getBlock(blockHash)
          if blkOpt.isSome:
            discard txoIdx.removeBlock(blkOpt.get(), blockHash, prevHash, height)
          else:
            warn "txospenderindex: disconnectHook could not read block body, skipping erase",
                 height = height, hash = $blockHash
        except CatchableError as e:
          warn "txospenderindex: disconnectHook removeBlock raised, continuing",
               height = height, hash = $blockHash, error = e.msg
        except Exception as e:
          warn "txospenderindex: disconnectHook removeBlock raised non-Catchable, continuing",
               height = height, hash = $blockHash, error = e.msg

  # 6. Initialize sync manager
  info "initializing sync manager"
  state.syncManager = newSyncManager(state.peerManager, state.chainState.db, params,
                                     state.chainState, config.numVerifyWorkers,
                                     state.blockFilterIndex, state.coinStatsIndex,
                                     state.txoSpenderIndex)
  state.syncManager.chainTip = state.chainState.bestBlockHash
  state.syncManager.chainTipHeight = state.chainState.bestHeight

  # 6a. IBD backfill of the block-filter index.  If --blockfilterindex was
  # toggled on AFTER an initial IBD, walk the chain from the index's
  # last-known height up to the chain tip and emit a filter for every
  # block.  This handles two distinct populating scenarios:
  #
  #   - Fresh datadir, flag was on: nothing to do (bestHeight == -1 == tip-1
  #     after genesis connect; the live connectBlock hook handles it from
  #     here).
  #   - Existing datadir, flag flipped on at restart: walk the gap.  For
  #     each height we read the block (cfBlocks) + the per-block undo from
  #     rev*.dat (when present) and call addBlock().  Blocks connected via
  #     the IBD fast path (connectBlockIBD) DO NOT have undo on disk; their
  #     filter will be output-only (BIP-158 elements include outputs +
  #     spent prevout scriptPubKeys, so this is partial — operator-visible
  #     limitation of nimrod's IBD shortcut).  Covered by the "still being
  #     indexed" REST 404 on those heights and a startup-log warn.
  #
  # Reference: bitcoin-core/src/index/base.cpp::BaseIndex::ThreadSync — Core
  # also walks the gap on startup; we run synchronously here because nimrod
  # currently has no async index thread, the operation is fast in practice
  # for the (tip - filterIndexHeight) gap on a flag flip.
  if state.blockFilterIndex != nil and state.blockFilterIndex.enabled:
    let csForBackfill = state.chainState
    let tipHeight = csForBackfill.bestHeight
    let startHeight = state.blockFilterIndex.bestHeight + 1
    if startHeight <= tipHeight:
      info "blockfilterindex: backfilling",
           fromHeight = startHeight, toHeight = tipHeight,
           gap = (tipHeight - startHeight + 1)
      var indexed = 0
      var partial = 0
      var skipped = 0
      for h in startHeight .. tipHeight:
        let hashOpt = csForBackfill.db.getBlockHashByHeight(h)
        if hashOpt.isNone:
          warn "blockfilterindex: missing height->hash, stopping backfill",
               height = h
          break
        let hash = hashOpt.get()
        let blkOpt = csForBackfill.db.getBlock(hash)
        if blkOpt.isNone:
          warn "blockfilterindex: missing block body, skipping",
               height = h, hash = $hash
          inc skipped
          continue
        let blk = blkOpt.get()

        # Try to load the per-block undo.  Genesis (txs.len == 1, all
        # coinbases) has none-by-construction; IBD-fast-path blocks have
        # null undoPos.  In both cases we proceed with empty undo (the
        # filter is then output-only).
        var blockUndo = chainstate.BlockUndo()
        let idxOpt = csForBackfill.db.getBlockIndex(hash)
        if idxOpt.isSome:
          let idx = idxOpt.get()
          # FlatFilePos is "null" when fileNum or pos is negative; same predicate
          # as storage/undo.nim::isNull (inlined to avoid pulling the undo
          # module into nimrod.nim — chainstate already re-exports the type).
          if idx.undoPos.fileNum >= 0 and idx.undoPos.pos >= 0:
            let (loaded, ok) = csForBackfill.undoMgr.readBlockUndo(
              idx.undoPos, blk.header.prevBlock, params)
            if ok:
              blockUndo = loaded
            else:
              inc partial
          else:
            # No undo on disk (genesis or IBD fast-path) — empty undo.
            if h > 0 and blk.txs.len > 1:
              inc partial

        if state.blockFilterIndex.addBlock(blk, hash, h, blockUndo):
          inc indexed
        else:
          inc skipped

        if (indexed + skipped) mod 10_000 == 0:
          info "blockfilterindex: backfill progress",
               indexed = indexed, skipped = skipped, partial = partial,
               currentHeight = h
      info "blockfilterindex: backfill complete",
           indexed = indexed, skipped = skipped, partial = partial,
           bestHeight = state.blockFilterIndex.bestHeight

  # 6b. IBD backfill of the coinstatsindex — symmetric to 6a.  On a fresh
  # datadir this walks at least genesis (height 0), establishing the index's
  # currentBlockHash so the first live connect (height 1) matches its parent
  # check.  On an existing datadir with the flag freshly flipped on it walks the
  # whole gap, folding each block's created outputs into the running MuHash and
  # removing its spent coins via the per-block undo.  The accumulator MUST be
  # exact for the per-height muhash to match Core byte-for-byte, so we require
  # real undo for non-coinbase blocks (a block with spends but no undo on disk
  # cannot be folded correctly — the IBD fast path does not persist undo, so a
  # coinstatsindex enabled only after such an IBD is logged as partial).
  # Reference: bitcoin-core/src/index/base.cpp::BaseIndex::ThreadSync.
  if state.coinStatsIndex != nil and state.coinStatsIndex.enabled:
    let csForCsi = state.chainState
    let tipHeightCsi = csForCsi.bestHeight
    let startHeightCsi = state.coinStatsIndex.bestHeight + 1
    if startHeightCsi <= tipHeightCsi:
      info "coinstatsindex: backfilling",
           fromHeight = startHeightCsi, toHeight = tipHeightCsi,
           gap = (tipHeightCsi - startHeightCsi + 1)
      var csiIndexed = 0
      var csiPartial = 0
      var csiSkipped = 0
      for h in startHeightCsi .. tipHeightCsi:
        let hashOpt = csForCsi.db.getBlockHashByHeight(h)
        if hashOpt.isNone:
          warn "coinstatsindex: missing height->hash, stopping backfill",
               height = h
          break
        let hash = hashOpt.get()
        let blkOpt = csForCsi.db.getBlock(hash)
        if blkOpt.isNone:
          warn "coinstatsindex: missing block body, stopping backfill",
               height = h, hash = $hash
          break
        let blk = blkOpt.get()

        var blockUndo = chainstate.BlockUndo()
        let idxOpt = csForCsi.db.getBlockIndex(hash)
        if idxOpt.isSome:
          let bidx = idxOpt.get()
          if bidx.undoPos.fileNum >= 0 and bidx.undoPos.pos >= 0:
            let (loaded, ok) = csForCsi.undoMgr.readBlockUndo(
              bidx.undoPos, blk.header.prevBlock, params)
            if ok:
              blockUndo = loaded
            else:
              inc csiPartial
          else:
            # No undo on disk (genesis or IBD fast-path).  Genesis legitimately
            # has none; a non-coinbase block without undo cannot be folded
            # exactly (would diverge from Core's per-height muhash).
            if h > 0 and blk.txs.len > 1:
              inc csiPartial

        if state.coinStatsIndex.addBlock(blk, hash, h, blockUndo):
          inc csiIndexed
        else:
          inc csiSkipped
          warn "coinstatsindex: addBlock failed during backfill, stopping",
               height = h, hash = $hash
          break

        if (csiIndexed + csiSkipped) mod 10_000 == 0:
          info "coinstatsindex: backfill progress",
               indexed = csiIndexed, skipped = csiSkipped,
               partial = csiPartial, currentHeight = h
      info "coinstatsindex: backfill complete",
           indexed = csiIndexed, skipped = csiSkipped, partial = csiPartial,
           bestHeight = state.coinStatsIndex.bestHeight

  # 6c. IBD backfill of the txospenderindex — symmetric to 6a/6b, but simpler:
  # it needs ONLY the block body (keys derive from the block's own inputs; no
  # undo required), so it can always be folded exactly even over IBD fast-path
  # heights that lack on-disk undo.  On a fresh datadir with the flag on this is
  # a no-op (the live connect hook handles it); on an existing datadir with the
  # flag freshly flipped on it walks the whole gap genesis..tip.
  # Reference: bitcoin-core/src/index/base.cpp::BaseIndex::ThreadSync.
  if state.txoSpenderIndex != nil and state.txoSpenderIndex.enabled:
    let csForTso = state.chainState
    let tipHeightTso = csForTso.bestHeight
    let startHeightTso = state.txoSpenderIndex.bestHeight + 1
    if startHeightTso <= tipHeightTso:
      info "txospenderindex: backfilling",
           fromHeight = startHeightTso, toHeight = tipHeightTso,
           gap = (tipHeightTso - startHeightTso + 1)
      var tsoIndexed = 0
      var tsoSkipped = 0
      for h in startHeightTso .. tipHeightTso:
        let hashOpt = csForTso.db.getBlockHashByHeight(h)
        if hashOpt.isNone:
          warn "txospenderindex: missing height->hash, stopping backfill",
               height = h
          break
        let hash = hashOpt.get()
        let blkOpt = csForTso.db.getBlock(hash)
        if blkOpt.isNone:
          warn "txospenderindex: missing block body, stopping backfill",
               height = h, hash = $hash
          break
        if state.txoSpenderIndex.addBlock(blkOpt.get(), hash, h,
                                          chainstate.BlockUndo()):
          inc tsoIndexed
        else:
          inc tsoSkipped
          warn "txospenderindex: addBlock failed during backfill, stopping",
               height = h, hash = $hash
          break
        if (tsoIndexed + tsoSkipped) mod 10_000 == 0:
          info "txospenderindex: backfill progress",
               indexed = tsoIndexed, skipped = tsoSkipped, currentHeight = h
      info "txospenderindex: backfill complete",
           indexed = tsoIndexed, skipped = tsoSkipped,
           bestHeight = state.txoSpenderIndex.bestHeight

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
    # Wire the BIP-157 filter index so submitblock populates it alongside
    # the live P2P sync path.  nil when --blockfilterindex is OFF.
    state.rpcServer.filterIndex = state.blockFilterIndex
    # Wire the coinstatsindex so submitblock maintains it alongside the live
    # P2P sync path, and gettxoutsetinfo / getindexinfo can read it.  nil when
    # --coinstatsindex is OFF (then a non-tip hash_or_height errors -8).
    state.rpcServer.coinStatsIndex = state.coinStatsIndex
    # Wire the txospenderindex so submitblock maintains it alongside the live
    # P2P sync path, and gettxspendingprevout / getindexinfo can read it.  nil
    # when --txospenderindex is OFF (then gettxspendingprevout can answer only
    # mempool spends and otherwise errors -1 "txospenderindex is unavailable.").
    state.rpcServer.txoSpenderIndex = state.txoSpenderIndex
    # Wire the ASMap manager so getpeerinfo can populate mapped_as.
    # W115 FIX-50: netGroupManager is always non-nil after step 5a above;
    # usingAsmap() returns false when no file was given / load failed.
    state.rpcServer.netGroupManager = state.netGroupManager
    # Wire the tx orphanage so getorphantxs can enumerate held orphans.
    # Same OrphanPool the message-dispatch path adds to (state.orphanPool);
    # nil-safe in the handler for test rigs that don't run a live pool.
    state.rpcServer.orphanPool = state.orphanPool
    # Wire the multi-wallet manager so createwallet / loadwallet / getnewaddress
    # and the rest of the wallet RPCs work. Without this the field stays nil and
    # every wallet handler early-returns "wallet functionality not enabled".
    # Wallets live under <datadir>/<network>/wallets (Core per-network layout);
    # newWalletManager creates that dir on demand.
    state.rpcServer.walletManager =
      newWalletManager(networkDir, params, state.chainState)

    # Auto-load wallets marked load_on_startup (or the default wallet). This is
    # fast and stays synchronous here because the wallet RPCs need the wallets
    # loaded before the RPC thread starts serving.
    #
    # The per-wallet reconcile to tip (restore the crash-safe snapshot and scan
    # the gap [lastSyncedHeight+1 .. tip] so a wallet left behind by an unclean
    # exit or by the live P2P/IBD block-connect path catches up — DATA-LOSS FIX
    # wa0fq5wtk) is NOT run here: it is deferred to a background OS thread
    # (walletReconcileThreadMain) spawned AFTER the RPC thread + P2P listener
    # come up.  Rationale: when a wallet's lastSyncedHeight is -1 (first restart
    # after this fix deploys, or a seed-restored wallet) the gap is the whole
    # chain 0..tip — ~950k blocks on mainnet — so scanning it on the boot path
    # left the node looking DOWN (RPC refused) for many minutes.  Core keeps RPC
    # responsive while the wallet rescans; we mirror that.  Best-effort — never
    # aborts node startup.
    try:
      let loadErrs = state.rpcServer.walletManager.loadWalletsAtStartup()
      for (wname, werr) in loadErrs:
        warn "wallet failed to load at startup", wallet = wname, error = werr
    except CatchableError as e:
      warn "wallet startup load failed", error = e.msg
    except Exception as e:
      warn "wallet startup load failed", error = e.msg
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

  # 7a. (BIP-157 block-filter index init was moved to step 5b above so the
  # SyncManager can be wired with it from construction.)

  # 7c. Start REST HTTP server (default OFF, --rest gate, Core parity).
  if config.restEnabled:
    let restPort =
      if config.restPort != 0: config.restPort
      else: uint16(int(config.rpcPort) + 1000)
    info "starting REST server", port = restPort,
      tls = (config.rpcTlsCert.len > 0 and config.rpcTlsKey.len > 0)
    try:
      state.restServer = newRestServer(
        restPort,
        state.chainState,
        state.mempool,
        params,
        txIndex = nil,
        filterIndex = state.blockFilterIndex,
        tlsCertPath = config.rpcTlsCert,
        tlsKeyPath = config.rpcTlsKey
      )
    except CatchableError as e:
      # W119 + FIX-64: misconfigured TLS (missing file, bad cert, only one
      # of cert/key set) must be fatal so the operator notices instead of
      # the listener silently dropping to plaintext or failing to start.
      fatal "REST/TLS configuration error", error = e.msg,
        cert = config.rpcTlsCert, key = config.rpcTlsKey
      quit(1)
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

  # 9. Start the sync loop and peer-manager main loop FIRST, as independent
  #    background tasks.
  #
  #    These MUST be spawned before outbound connections are started.
  #    startOutboundConnections() dials DNS-seed addresses serially, awaiting
  #    each connect; an unreachable address can block for the full TCP connect
  #    timeout, so filling all outbound slots can take many minutes.  When it
  #    was `await`ed here (before syncLoop was spawned), a slow connection
  #    phase meant syncLoop() was never started at all: the node connected to
  #    peers but never sent a single `getheaders`, so it sat idle at its
  #    restart height forever.  (mainnet incident 2026-05-20: nimrod stuck at
  #    block 950146 — syncLoop never spawned.)
  #
  #    syncLoop polls peerManager for a sync peer every iteration, so it
  #    correctly picks up peers as the background connection task fills slots.
  #    Bitcoin Core runs outbound dialing in its own ThreadOpenConnections,
  #    fully decoupled from chain sync — this mirrors that.
  info "starting sync"
  asyncSpawn state.syncManager.syncLoop()
  asyncSpawn state.peerManager.mainLoop()

  # 10. Start outbound connections in the background.  It fills outbound slots
  #     over time without blocking node startup or the sync loop above.
  info "connecting to peers"
  asyncSpawn state.peerManager.startOutboundConnections()

  # 10a. Deferred wallet history rescan (DATA-LOSS FIX wa0fq5wtk), now that the
  #      RPC thread, P2P listener and sync loop are all up.  Running this on its
  #      own OS thread keeps a full-chain scan (lastSyncedHeight = -1: first
  #      restart after the wallet fix, or a seed-restore) off the boot path so
  #      RPC stays bound and responsive throughout — Core CWallet::AttachChain
  #      parity (getwalletinfo.scanning).  Only relevant when wallets/RPC are
  #      enabled (walletManager is nil otherwise).  See
  #      walletReconcileThreadMain for the lifetime/gcsafe rationale; the thread
  #      handle is pinned on `state` to avoid the `addr(t)` SIGSEGV the RPC/REST
  #      threads document.
  if state.rpcServer != nil and state.rpcServer.walletManager != nil:
    info "starting background wallet reconcile"
    createThread(state.walletReconcileThread, walletReconcileThreadMain,
                 state.rpcServer.walletManager)

  # 11a. Startup ASMapHealthCheck (G16/G28 FIX-52).
  # Logs unique ASNs / mapped / unmapped across the initial known-address pool.
  # Reference: bitcoin-core/src/init.cpp — calls netgroupman.ASMapHealthCheck()
  # after loading peers.dat.
  state.peerManager.runAsmapHealthCheck()
  state.lastAsmapHealthCheck = getTime().toUnix()

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

    # Periodic ASMapHealthCheck — every 3600 s.
    # Reference: bitcoin-core/src/netgroup.cpp ASMapHealthCheck() is also
    # called from addrman's periodic logic.  Here we mirror the 1-hour cadence
    # described in the audit (W115 G16/G28).
    let nowUnix = getTime().toUnix()
    if nowUnix - state.lastAsmapHealthCheck >= 3600:
      state.peerManager.runAsmapHealthCheck()
      state.lastAsmapHealthCheck = nowUnix

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
