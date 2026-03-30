## nimrod - Bitcoin full node in Nim
## Unified CLI with subcommands for node operation, RPC interaction, and wallet management

import std/[parseopt, os, strutils, json, posix, net, base64]
import chronos
import chronicles

import ./primitives/[types, serialize]
import ./consensus/params
import ./storage/[db, chainstate]
import ./network/[peer, peermanager, sync, messages]
import ./mempool/mempool
import ./mining/fees
import ./rpc/server
import ./crypto/secp256k1

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

  NodeState* = ref object
    config*: NimrodConfig
    params*: ConsensusParams
    chainState*: ChainState
    mempool*: Mempool
    peerManager*: PeerManager
    syncManager*: SyncManager
    feeEstimator*: FeeEstimator
    rpcServer*: RpcServer
    crypto*: CryptoEngine
    running*: bool

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
    pruneTarget: 0  # Pruning disabled by default
  )

proc loadConfigFile*(config: var NimrodConfig) =
  ## Load configuration from dataDir/nimrod.conf
  let confPath = config.dataDir / "nimrod.conf"
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
  --prune=SIZE_MB        Enable pruning to keep SIZE_MB of blocks (min: 550)
  -h, --help             Show this help
  -v, --version          Show version

Config file: $datadir/nimrod.conf (key=value format)
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
          elif pruneMiB > 0 and pruneMiB < 550:
            echo "Prune configured below the minimum of 550 MiB"
            quit(1)
          result.config.pruneTarget = uint64(pruneMiB)
        except ValueError:
          echo "Invalid prune value: " & p.val
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

proc handleMessage(state: NodeState, peer: Peer, msg: P2PMessage) {.async.} =
  ## Handle incoming P2P messages
  case msg.kind
  of mkHeaders:
    await state.syncManager.handleHeaders(peer, msg.headers)

  of mkBlock:
    discard state.syncManager.processBlock(msg.blk)

  of mkTx:
    var accepted = false
    {.gcsafe.}:
      try:
        let txResult = state.mempool.acceptTransaction(msg.tx, state.crypto)
        accepted = txResult.isOk
      except CatchableError:
        discard
      except Exception:
        discard
    if accepted:
      # Relay to peers
      asyncSpawn state.peerManager.broadcastTx(msg.tx)

  of mkInv:
    # Request blocks we don't have
    var blockInvs: seq[InvVector]
    for item in msg.invItems:
      if item.invType == invBlock or item.invType == invWitnessBlock:
        # Request as witness block for segwit support
        blockInvs.add(InvVector(invType: invWitnessBlock, hash: item.hash))
    if blockInvs.len > 0:
      asyncSpawn peer.sendGetData(blockInvs)

  of mkGetData:
    # Handle data requests - serve blocks to peers
    for item in msg.getData:
      if item.invType == invBlock or item.invType == invWitnessBlock:
        let blockOpt = state.chainState.db.getBlock(BlockHash(item.hash))
        if blockOpt.isSome:
          let blkMsg = newBlockMsg(blockOpt.get())
          try:
            await peer.sendMessage(blkMsg)
            debug "served block to peer", peer = $peer
          except CatchableError as e:
            debug "failed to serve block", peer = $peer, error = e.msg

  of mkPing:
    # Respond with pong
    discard

  else:
    discard

proc messageCallback(state: NodeState): peer.PeerCallback =
  ## Create message callback for peer manager
  proc callback(peer: Peer, msg: P2PMessage): Future[void] {.async.} =
    await handleMessage(state, peer, msg)
  return callback

proc setupSignalHandlers*() =
  ## Setup SIGINT/SIGTERM handlers for graceful shutdown
  proc sigHandler(sig: cint) {.noconv.} =
    echo "\nReceived signal " & $sig & ", shutting down..."

    if globalNodeState != nil:
      globalNodeState.running = false

      # Flush UTXO cache
      if globalNodeState.chainState != nil:
        info "flushing UTXO cache"
        globalNodeState.chainState.flushCache()

      # Stop RPC server
      if globalNodeState.rpcServer != nil:
        info "stopping RPC server"
        globalNodeState.rpcServer.stop()

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

proc startNode*(config: NimrodConfig) {.async.} =
  ## Start the node
  ## Init order: db -> chainstate -> mempool -> peermanager -> sync -> fee estimator -> RPC -> P2P
  let params = getConsensusParams(config)

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
    running: true
  )
  {.gcsafe.}:
    globalNodeState = state

  # 1. Initialize crypto engine
  info "initializing crypto engine"
  state.crypto = newCryptoEngine()

  # 2. Open database and chainstate
  info "opening database", path = networkDir / "chainstate"
  state.chainState = newChainState(networkDir / "chainstate", params)

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

  # 3. Initialize mempool
  info "initializing mempool"
  state.mempool = newMempool(state.chainState, params)

  # 4. Initialize fee estimator
  info "initializing fee estimator"
  state.feeEstimator = newFeeEstimator()

  # 5. Initialize peer manager
  info "initializing peer manager"
  state.peerManager = newPeerManager(params, maxOut = config.maxConnections div 16, maxIn = config.maxConnections - config.maxConnections div 16)
  state.peerManager.updateHeight(state.chainState.bestHeight)
  state.peerManager.setMessageCallback(messageCallback(state))

  # 6. Initialize sync manager
  info "initializing sync manager"
  state.syncManager = newSyncManager(state.peerManager, state.chainState.db, params, state.chainState)
  state.syncManager.chainTip = state.chainState.bestBlockHash
  state.syncManager.chainTipHeight = state.chainState.bestHeight

  # 7. Start RPC server
  if config.rpcEnabled:
    info "starting RPC server", port = config.rpcPort
    state.rpcServer = newRpcServer(
      config.rpcPort,
      state.chainState,
      state.mempool,
      state.peerManager,
      state.feeEstimator,
      params,
      config.rpcUser,
      config.rpcPassword
    )
    asyncSpawn state.rpcServer.start()

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

proc main() =
  let (cmd, config, args) = parseArgs()

  case cmd
  of cmdStart:
    setupSignalHandlers()
    waitFor startNode(config)

  of cmdHelp:
    showHelp()

  of cmdVersion:
    echo "nimrod v" & NimrodVersion

  else:
    # Run RPC command
    waitFor runCommand(cmd, config, args)

when isMainModule:
  main()
