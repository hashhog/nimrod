## nimrod - Bitcoin full node in Nim
## Main entry point

import std/[parseopt, os, strutils]
import chronicles

const NimrodVersion* = "0.1.0"

type
  NimrodConfig* = object
    dataDir*: string
    network*: string
    rpcPort*: uint16
    p2pPort*: uint16
    logLevel*: string
    maxConnections*: int
    rpcEnabled*: bool

proc defaultConfig*(): NimrodConfig =
  NimrodConfig(
    dataDir: getHomeDir() / ".nimrod",
    network: "mainnet",
    rpcPort: 8332,
    p2pPort: 8333,
    logLevel: "info",
    maxConnections: 125,
    rpcEnabled: true
  )

proc parseArgs(): NimrodConfig =
  result = defaultConfig()

  var p = initOptParser()
  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdShortOption, cmdLongOption:
      case p.key.toLowerAscii
      of "datadir", "d":
        result.dataDir = p.val
      of "network", "n":
        result.network = p.val
      of "rpcport":
        result.rpcPort = uint16(parseInt(p.val))
      of "port", "p":
        result.p2pPort = uint16(parseInt(p.val))
      of "loglevel", "l":
        result.logLevel = p.val
      of "maxconnections":
        result.maxConnections = parseInt(p.val)
      of "norpc":
        result.rpcEnabled = false
      of "testnet":
        result.network = "testnet3"
        result.rpcPort = 18332
        result.p2pPort = 18333
      of "regtest":
        result.network = "regtest"
        result.rpcPort = 18443
        result.p2pPort = 18444
      of "help", "h":
        echo """
nimrod v""" & NimrodVersion & """

A Bitcoin full node in Nim

Usage: nimrod [options]

Options:
  -d, --datadir=DIR     Data directory (default: ~/.nimrod)
  -n, --network=NET     Network: mainnet, testnet3, regtest (default: mainnet)
  --testnet             Use testnet3
  --regtest             Use regtest
  --rpcport=PORT        RPC port (default: 8332)
  -p, --port=PORT       P2P port (default: 8333)
  -l, --loglevel=LEVEL  Log level: trace, debug, info, warn, error (default: info)
  --maxconnections=N    Maximum peer connections (default: 125)
  --norpc               Disable RPC server
  -h, --help            Show this help
  -v, --version         Show version
"""
        quit(0)
      of "version", "v":
        echo "nimrod v" & NimrodVersion
        quit(0)
      else:
        echo "Unknown option: " & p.key
        quit(1)
    of cmdArgument:
      echo "Unexpected argument: " & p.key
      quit(1)

proc main() =
  let config = parseArgs()

  # Create data directory
  if not dirExists(config.dataDir):
    createDir(config.dataDir)

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

  # Placeholder for actual node startup
  # In full implementation:
  # 1. Load chainstate from database
  # 2. Start peer manager and connect to network
  # 3. Start block sync
  # 4. Start RPC server
  # 5. Enter main event loop

  echo ""
  echo "Node scaffold initialized. Full functionality coming soon..."

when isMainModule:
  main()
