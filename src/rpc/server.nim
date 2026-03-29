## JSON-RPC server
## Bitcoin Core compatible RPC interface with HTTP Basic auth
## JSON-RPC 2.0 compliant with proper error codes

import std/[json, strutils, tables, options, base64, parseutils, times, sets, os, algorithm]
import chronos
import chronicles
import jsony
import ../primitives/[types, serialize]
import ../consensus/[params, validation, chain]
import ../storage/[chainstate, blockstore]
import ../mempool/[mempool, package]
import ../crypto/[hashing, secp256k1, address]
import ../network/[peer, peermanager, banman]
import ../mining/[fees, blocktemplate]
import ../wallet/wallet
import ../wallet/descriptor
import ../wallet/manager
import ../wallet/psbt
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
    running*: bool
    crypto*: CryptoEngine
    blockFileManager*: BlockFileManager  ## Optional: for pruning support
    wallet*: Wallet                      ## Deprecated: use walletManager
    walletManager*: WalletManager        ## Multi-wallet manager
    currentWalletName*: string           ## Current request's target wallet name
    zmq*: ZmqNotificationInterface       ## Optional: ZMQ notification interface

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
  RpcInvalidAddressOrKey* = -5     # Invalid address or key
  RpcTransactionError* = -25       # Generic transaction error
  RpcTransactionRejected* = -26    # Transaction rejected by mempool
  RpcTransactionAlreadyInChain* = -27  # Transaction already confirmed
  RpcMiscError* = -1               # Generic misc error

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
  authPass: string = ""
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
    running: false,
    crypto: newCryptoEngine()
  )

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

# Blockchain RPCs
proc handleGetBlockchainInfo(rpc: RpcServer): JsonNode =
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
    medianTime = int64(tip.header.timestamp)  # Simplified: real impl would compute median

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

  # Get pruning info
  var pruned = false
  var pruneHeight: int32 = -1
  var sizeOnDisk: uint64 = 0

  if rpc.blockFileManager != nil:
    pruned = rpc.blockFileManager.isPruneMode
    sizeOnDisk = rpc.blockFileManager.calculateCurrentUsage()
    if pruned:
      pruneHeight = rpc.blockFileManager.getPruneHeight()

  var response = %*{
    "chain": chainName,
    "blocks": rpc.chainState.bestHeight,
    "headers": rpc.chainState.bestHeight,
    "bestblockhash": reverseHex(toHex(array[32, byte](rpc.chainState.bestBlockHash))),
    "bits": toHex(cast[array[4, byte]]([
      byte(bits and 0xff),
      byte((bits shr 8) and 0xff),
      byte((bits shr 16) and 0xff),
      byte((bits shr 24) and 0xff)
    ])),
    "target": reverseHex(toHex(target)),
    "difficulty": targetToDifficulty(target),
    "time": blockTime,
    "mediantime": medianTime,
    "verificationprogress": verificationProgress,
    "initialblockdownload": rpc.chainState.bestHeight < 100,
    "chainwork": toHex(rpc.chainState.totalWork),
    "size_on_disk": sizeOnDisk,
    "pruned": pruned,
    "warnings": ""
  }

  # Add pruneheight only if pruned
  if pruned and pruneHeight >= 0:
    response["pruneheight"] = %pruneHeight

  # Add prune_target_size if pruning is enabled
  if rpc.blockFileManager != nil and rpc.blockFileManager.isPruneMode:
    response["prune_target_size"] = %rpc.blockFileManager.getPruneTarget()

  response

proc handleGetBlockCount(rpc: RpcServer): JsonNode =
  %rpc.chainState.bestHeight

proc handleGetBestBlockHash(rpc: RpcServer): JsonNode =
  %reverseHex(toHex(array[32, byte](rpc.chainState.bestBlockHash)))

proc handleGetBlockHash(rpc: RpcServer, params: JsonNode): JsonNode =
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing height parameter")

  let height = params[0].getInt()
  let hashOpt = rpc.chainState.db.getBlockHashByHeight(int32(height))
  if hashOpt.isNone:
    raise newRpcError(RpcInvalidParams, "block height out of range")

  %reverseHex(toHex(array[32, byte](hashOpt.get())))

proc handleGetBlockHeader(rpc: RpcServer, params: JsonNode): JsonNode =
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing blockhash parameter")

  let hashHex = params[0].getStr()
  let verbose = if params.len >= 2: params[1].getBool() else: true

  let blockHash = parseBlockHash(hashHex)
  let idxOpt = rpc.chainState.db.getBlockIndex(blockHash)
  if idxOpt.isNone:
    raise newRpcError(RpcInvalidParams, "block not found")

  let idx = idxOpt.get()

  if not verbose:
    # Return raw hex
    let headerBytes = serialize(idx.header)
    return %toHex(headerBytes)

  let target = bitsToTarget(idx.header.bits)

  var response = %*{
    "hash": reverseHex(toHex(array[32, byte](idx.hash))),
    "confirmations": rpc.chainState.bestHeight - idx.height + 1,
    "height": idx.height,
    "version": idx.header.version,
    "versionHex": toHex(cast[array[4, byte]]([
      byte(idx.header.version and 0xff),
      byte((idx.header.version shr 8) and 0xff),
      byte((idx.header.version shr 16) and 0xff),
      byte((idx.header.version shr 24) and 0xff)
    ])),
    "merkleroot": reverseHex(toHex(idx.header.merkleRoot)),
    "time": idx.header.timestamp,
    "mediantime": idx.header.timestamp,
    "nonce": idx.header.nonce,
    "bits": toHex(cast[array[4, byte]]([
      byte(idx.header.bits and 0xff),
      byte((idx.header.bits shr 8) and 0xff),
      byte((idx.header.bits shr 16) and 0xff),
      byte((idx.header.bits shr 24) and 0xff)
    ])),
    "difficulty": targetToDifficulty(target),
    "chainwork": toHex(idx.totalWork),
    "nTx": 0
  }

  # Add previousblockhash if not genesis
  if idx.height > 0:
    response["previousblockhash"] = %reverseHex(toHex(array[32, byte](idx.prevHash)))

  # Add nextblockhash if not tip
  if idx.height < rpc.chainState.bestHeight:
    let nextHashOpt = rpc.chainState.db.getBlockHashByHeight(idx.height + 1)
    if nextHashOpt.isSome:
      response["nextblockhash"] = %reverseHex(toHex(array[32, byte](nextHashOpt.get())))

  response

proc handleGetBlock(rpc: RpcServer, params: JsonNode): JsonNode =
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing blockhash parameter")

  let hashHex = params[0].getStr()
  let verbosity = if params.len >= 2: params[1].getInt() else: 1

  let blockHash = parseBlockHash(hashHex)

  # Check if block has been pruned
  if rpc.blockFileManager != nil and rpc.blockFileManager.isBlockPruned(blockHash):
    raise newRpcError(RpcMiscError, "Block not available (pruned data)")

  let blkOpt = rpc.chainState.db.getBlock(blockHash)
  if blkOpt.isNone:
    raise newRpcError(RpcInvalidParams, "block not found")

  let b = blkOpt.get()

  if verbosity == 0:
    # Return raw hex
    return %toHex(serialize(b))

  let headerBytes = serialize(b.header)
  let computedHash = doubleSha256(headerBytes)

  # Get block index for height
  let idxOpt = rpc.chainState.db.getBlockIndex(blockHash)
  let height = if idxOpt.isSome: idxOpt.get().height else: 0'i32

  var txids: seq[string]
  for tx in b.txs:
    let txBytes = serialize(tx)
    let txid = doubleSha256(txBytes)
    txids.add(reverseHex(toHex(txid)))

  let target = bitsToTarget(b.header.bits)

  var response = %*{
    "hash": reverseHex(toHex(computedHash)),
    "confirmations": rpc.chainState.bestHeight - height + 1,
    "size": serialize(b).len,
    "weight": calculateBlockWeight(b),
    "height": height,
    "version": b.header.version,
    "versionHex": toHex(cast[array[4, byte]]([
      byte(b.header.version and 0xff),
      byte((b.header.version shr 8) and 0xff),
      byte((b.header.version shr 16) and 0xff),
      byte((b.header.version shr 24) and 0xff)
    ])),
    "merkleroot": reverseHex(toHex(b.header.merkleRoot)),
    "tx": txids,
    "time": b.header.timestamp,
    "mediantime": b.header.timestamp,
    "nonce": b.header.nonce,
    "bits": toHex(cast[array[4, byte]]([
      byte(b.header.bits and 0xff),
      byte((b.header.bits shr 8) and 0xff),
      byte((b.header.bits shr 16) and 0xff),
      byte((b.header.bits shr 24) and 0xff)
    ])),
    "difficulty": targetToDifficulty(target),
    "chainwork": "0",
    "nTx": b.txs.len
  }

  if height > 0:
    response["previousblockhash"] = %reverseHex(toHex(array[32, byte](b.header.prevBlock)))

  if height < rpc.chainState.bestHeight:
    let nextHashOpt = rpc.chainState.db.getBlockHashByHeight(height + 1)
    if nextHashOpt.isSome:
      response["nextblockhash"] = %reverseHex(toHex(array[32, byte](nextHashOpt.get())))

  response

proc handleGetDifficulty(rpc: RpcServer): JsonNode =
  var bits = rpc.params.genesisBits

  # Get bits from current tip if available
  let blkOpt = rpc.chainState.db.getBlock(rpc.chainState.bestBlockHash)
  if blkOpt.isSome:
    bits = blkOpt.get().header.bits

  let target = bitsToTarget(bits)
  %targetToDifficulty(target)

proc handleGetChainTips(rpc: RpcServer): JsonNode =
  # For now, just return the active tip
  # A full implementation would track multiple chain tips
  %*[{
    "height": rpc.chainState.bestHeight,
    "hash": reverseHex(toHex(array[32, byte](rpc.chainState.bestBlockHash))),
    "branchlen": 0,
    "status": "active"
  }]

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
  if hashHex.len != 64:
    raise newRpcError(RpcInvalidAddressOrKey, "Invalid block hash")

  let blockHash = parseBlockHash(hashHex)

  # Check if block exists
  let idxOpt = rpc.chainState.db.getBlockIndex(blockHash)
  if idxOpt.isNone:
    raise newRpcError(RpcInvalidAddressOrKey, "Block not found")

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
  if hashHex.len != 64:
    raise newRpcError(RpcInvalidAddressOrKey, "Invalid block hash")

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
  if hashHex.len != 64:
    raise newRpcError(RpcInvalidAddressOrKey, "Invalid block hash")

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
proc handleGetMempoolInfo(rpc: RpcServer): JsonNode =
  let minFee = rpc.mempool.minFeeRate / 100000000.0  # Convert sat/vbyte to BTC/kB
  %*{
    "loaded": true,
    "size": rpc.mempool.count,
    "bytes": rpc.mempool.size,
    "usage": rpc.mempool.size,
    "maxmempool": rpc.mempool.maxSize,
    "mempoolminfee": minFee,
    "minrelaytxfee": minFee
  }

proc handleGetRawMempool(rpc: RpcServer, params: JsonNode): JsonNode =
  let verbose = if params.len >= 1: params[1].getBool() else: false

  if verbose:
    var entries = newJObject()
    for txid, entry in rpc.mempool.entries:
      let vsize = (entry.weight + 3) div 4
      # Full RBF: all mempool transactions are replaceable
      entries[$txid] = %*{
        "vsize": vsize,
        "weight": entry.weight,
        "fee": float64(int64(entry.fee)) / 100000000.0,
        "time": entry.timeAdded.toUnix(),
        "height": entry.height,
        "descendantcount": 1,
        "descendantsize": vsize,
        "descendantfees": int64(entry.fee),
        "ancestorcount": 1,
        "ancestorsize": vsize,
        "ancestorfees": int64(entry.ancestorFee),
        "bip125-replaceable": true
      }
    return entries
  else:
    var txids: seq[string]
    for txid in rpc.mempool.entries.keys:
      txids.add(reverseHex(toHex(array[32, byte](txid))))
    return %txids

proc handleGetMempoolEntry(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Returns mempool data for a given transaction
  ## Reference: Bitcoin Core rpc/mempool.cpp getmempoolentry
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing txid parameter")

  let txidHex = params[0].getStr()
  if txidHex.len != 64:
    raise newRpcError(RpcInvalidAddressOrKey, "Invalid txid")

  # Parse txid (reverse byte order from hex display format)
  var txidBytes: array[32, byte]
  let reversed = reverseHex(txidHex)
  for i in 0 ..< 32:
    txidBytes[i] = byte(parseHexInt(reversed[i*2 .. i*2+1]))

  let txid = TxId(txidBytes)
  let entryOpt = rpc.mempool.get(txid)

  if entryOpt.isNone:
    raise newRpcError(RpcInvalidAddressOrKey, "Transaction not in mempool")

  let entry = entryOpt.get()
  let vsize = (entry.weight + 3) div 4
  let feeRate = float64(int64(entry.fee)) / float64(vsize) / 100000.0  # BTC/kvB

  # Full RBF: all mempool transactions are replaceable
  %*{
    "vsize": vsize,
    "weight": entry.weight,
    "fee": float64(int64(entry.fee)) / 100000000.0,
    "modifiedfee": float64(int64(entry.fee)) / 100000000.0,
    "time": entry.timeAdded.toUnix(),
    "height": entry.height,
    "descendantcount": 1,
    "descendantsize": vsize,
    "descendantfees": int64(entry.fee),
    "ancestorcount": entry.ancestorCount,
    "ancestorsize": entry.ancestorSize,
    "ancestorfees": int64(entry.ancestorFee),
    "wtxid": reverseHex(toHex(array[32, byte](entry.tx.wtxid()))),
    "fees": {
      "base": float64(int64(entry.fee)) / 100000000.0,
      "modified": float64(int64(entry.fee)) / 100000000.0,
      "ancestor": float64(int64(entry.ancestorFee)) / 100000000.0,
      "descendant": float64(int64(entry.fee)) / 100000000.0
    },
    "depends": [],  # TODO: calculate dependencies
    "spentby": [],  # TODO: calculate spenders
    "bip125-replaceable": true,
    "unbroadcast": false
  }

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

  # OP_RETURN: null data
  if script.len >= 1 and script[0] == 0x6a:
    return "nulldata"

  # Multisig: OP_M <pubkeys> OP_N OP_CHECKMULTISIG
  if script.len >= 4 and script[^1] == 0xae:
    let opM = script[0]
    let opN = script[^2]
    if opM >= 0x51 and opM <= 0x60 and opN >= 0x51 and opN <= 0x60:
      return "multisig"

  return "nonstandard"

proc extractAddressFromScript(script: seq[byte], mainnet: bool): Option[string] =
  ## Extract address from scriptPubKey if possible
  let scriptType = getScriptType(script)

  case scriptType
  of "pubkeyhash":
    # P2PKH: extract 20-byte hash
    var hash: array[20, byte]
    for i in 0 ..< 20:
      hash[i] = script[3 + i]
    let addrVal = Address(kind: P2PKH, pubkeyHash: hash)
    return some(encodeAddress(addrVal, mainnet))

  of "scripthash":
    # P2SH: extract 20-byte hash
    var hash: array[20, byte]
    for i in 0 ..< 20:
      hash[i] = script[2 + i]
    let addrVal = Address(kind: P2SH, scriptHash: hash)
    return some(encodeAddress(addrVal, mainnet))

  of "witness_v0_keyhash":
    # P2WPKH: extract 20-byte hash
    var hash: array[20, byte]
    for i in 0 ..< 20:
      hash[i] = script[2 + i]
    let addrVal = Address(kind: P2WPKH, wpkh: hash)
    return some(encodeAddress(addrVal, mainnet))

  of "witness_v0_scripthash":
    # P2WSH: extract 32-byte hash
    var hash: array[32, byte]
    for i in 0 ..< 32:
      hash[i] = script[2 + i]
    let addrVal = Address(kind: P2WSH, wsh: hash)
    return some(encodeAddress(addrVal, mainnet))

  of "witness_v1_taproot":
    # P2TR: extract 32-byte x-only pubkey
    var key: array[32, byte]
    for i in 0 ..< 32:
      key[i] = script[2 + i]
    let addrVal = Address(kind: P2TR, taprootKey: key)
    return some(encodeAddress(addrVal, mainnet))

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

proc buildScriptPubKeyJson(script: seq[byte], mainnet: bool): JsonNode =
  ## Build scriptPubKey JSON object with type, asm, hex, address
  let scriptType = getScriptType(script)
  let addrOpt = extractAddressFromScript(script, mainnet)

  result = %*{
    "asm": disassembleScript(script),
    "hex": toHex(script),
    "type": scriptType
  }

  if addrOpt.isSome:
    result["address"] = %addrOpt.get()

proc buildVinJson(tx: Transaction, inputIndex: int): JsonNode =
  ## Build vin JSON object for an input
  let inp = tx.inputs[inputIndex]
  let isCoinbase = inp.prevOut.txid == TxId(default(array[32, byte])) and
                   inp.prevOut.vout == 0xFFFFFFFF'u32

  if isCoinbase:
    result = %*{
      "coinbase": toHex(inp.scriptSig),
      "sequence": inp.sequence
    }
  else:
    result = %*{
      "txid": reverseHex(toHex(array[32, byte](inp.prevOut.txid))),
      "vout": inp.prevOut.vout,
      "scriptSig": %*{
        "asm": disassembleScript(inp.scriptSig),
        "hex": toHex(inp.scriptSig)
      },
      "sequence": inp.sequence
    }

  # Add witness data if present
  if tx.witnesses.len > inputIndex and tx.witnesses[inputIndex].len > 0:
    var txinwitness = newJArray()
    for item in tx.witnesses[inputIndex]:
      txinwitness.add(%toHex(item))
    result["txinwitness"] = txinwitness

proc buildVoutJson(output: TxOut, index: int, mainnet: bool): JsonNode =
  ## Build vout JSON object for an output
  %*{
    "value": float64(int64(output.value)) / 100_000_000.0,
    "n": index,
    "scriptPubKey": buildScriptPubKeyJson(output.scriptPubKey, mainnet)
  }

proc buildVerboseTxJson(tx: Transaction, blockHash: Option[BlockHash],
                        confirmations: int32, blocktime: uint32,
                        inActiveChain: Option[bool], mainnet: bool): JsonNode =
  ## Build complete verbose transaction JSON
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
    voutArray.add(buildVoutJson(outp, i, mainnet))
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

proc handleGetRawTransaction(rpc: RpcServer, params: JsonNode): JsonNode =
  ## getrawtransaction "txid" ( verbose "blockhash" )
  ##
  ## Returns raw transaction data. If verbose=false (default), returns hex string.
  ## If verbose=true, returns JSON object with decoded transaction data.
  ##
  ## By default, only mempool transactions are returned. With txindex enabled,
  ## confirmed transactions can also be retrieved. If blockhash is provided,
  ## the transaction is searched for only in that specific block.
  ##
  ## Reference: Bitcoin Core /src/rpc/rawtransaction.cpp getrawtransaction

  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing txid parameter")

  let txidHex = params[0].getStr()
  if txidHex.len != 64:
    raise newRpcError(RpcInvalidAddressOrKey, "Invalid txid")

  # Parse verbose parameter (supports bool or int)
  var verbose = false
  if params.len >= 2:
    if params[1].kind == JBool:
      verbose = params[1].getBool()
    elif params[1].kind == JInt:
      verbose = params[1].getInt() > 0
    elif params[1].kind == JNull:
      discard  # Keep default false
    else:
      raise newRpcError(RpcInvalidParams, "verbose must be a boolean or integer")

  let txid = parseTxId(txidHex)

  # Parse optional blockhash parameter
  var explicitBlockHash: Option[BlockHash] = none(BlockHash)
  if params.len >= 3 and params[2].kind == JString:
    let blockHashHex = params[2].getStr()
    if blockHashHex.len != 64:
      raise newRpcError(RpcInvalidAddressOrKey, "Invalid block hash")
    explicitBlockHash = some(parseBlockHash(blockHashHex))

  let mainnet = rpc.params.network == Mainnet

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

    # Search for transaction in block
    var foundTx: Option[Transaction] = none(Transaction)
    for tx in blk.txs:
      if tx.txid() == txid:
        foundTx = some(tx)
        break

    if foundTx.isNone:
      raise newRpcError(RpcInvalidAddressOrKey,
        "No such transaction found in the provided block. Use gettransaction for wallet transactions.")

    let tx = foundTx.get()

    if not verbose:
      return %toHex(serialize(tx))

    # Check if block is in active chain
    let blockIdx = idxOpt.get()
    let tipHashOpt = rpc.chainState.db.getBlockHashByHeight(rpc.chainState.bestHeight)
    var inActiveChain = false
    if tipHashOpt.isSome:
      # Block is in active chain if we can reach it from the tip by height
      let heightHashOpt = rpc.chainState.db.getBlockHashByHeight(blockIdx.height)
      inActiveChain = heightHashOpt.isSome and heightHashOpt.get() == blockHash

    let confirmations = if inActiveChain:
      rpc.chainState.bestHeight - blockIdx.height + 1
    else:
      -1'i32  # Not in active chain

    return buildVerboseTxJson(tx, some(blockHash), confirmations,
                              blk.header.timestamp, some(inActiveChain), mainnet)

  # No explicit blockhash: check mempool first, then txindex
  let mempoolTx = rpc.mempool.getTransaction(txid)
  if mempoolTx.isSome:
    let tx = mempoolTx.get()

    if not verbose:
      return %toHex(serialize(tx))

    # Unconfirmed transaction - no block info
    return buildVerboseTxJson(tx, none(BlockHash), 0, 0, none(bool), mainnet)

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

  if not verbose:
    return %toHex(serialize(tx))

  let idxOpt = rpc.chainState.db.getBlockIndex(loc.blockHash)
  let blockHeight = if idxOpt.isSome: idxOpt.get().height else: 0'i32
  let confirmations = rpc.chainState.bestHeight - blockHeight + 1

  buildVerboseTxJson(tx, some(loc.blockHash), confirmations,
                     blk.header.timestamp, none(bool), mainnet)

proc handleDecodeRawTransaction(rpc: RpcServer, params: JsonNode): JsonNode =
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing hexstring parameter")

  let txHex = params[0].getStr()

  try:
    let txBytes = hexToBytes(txHex)
    let tx = deserializeTransaction(txBytes)
    let txid = tx.txid()
    let wtxid = tx.wtxid()
    let weight = validation.calculateTransactionWeight(tx)

    var inputs = newJArray()
    for inp in tx.inputs:
      inputs.add(%*{
        "txid": reverseHex(toHex(array[32, byte](inp.prevOut.txid))),
        "vout": inp.prevOut.vout,
        "scriptSig": %*{
          "hex": toHex(inp.scriptSig)
        },
        "sequence": inp.sequence
      })

    var outputs = newJArray()
    for i, outp in tx.outputs:
      outputs.add(%*{
        "value": float64(int64(outp.value)) / 100000000.0,
        "n": i,
        "scriptPubKey": %*{
          "hex": toHex(outp.scriptPubKey)
        }
      })

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

  # Parse all transactions
  var txns: seq[Transaction]
  for i, rawTxNode in rawTxsArray:
    if rawTxNode.kind != JString:
      raise newRpcError(RpcInvalidParams, "rawtxs[" & $i & "] must be a hex string")

    let txHex = rawTxNode.getStr()
    try:
      let txBytes = hexToBytes(txHex)
      let tx = deserializeTransaction(txBytes)
      txns.add(tx)
    except CatchableError as e:
      raise newRpcError(RpcInvalidParams, "TX " & $i & " decode failed: " & e.msg)

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
proc handleGetNetworkInfo(rpc: RpcServer): JsonNode =
  ## Return information about P2P networking
  ## Reference: Bitcoin Core rpc/net.cpp getnetworkinfo
  let connCount = if rpc.peerManager != nil: rpc.peerManager.connectedPeerCount() else: 0
  let inCount = if rpc.peerManager != nil: rpc.peerManager.inboundCount() else: 0
  let outCount = if rpc.peerManager != nil: rpc.peerManager.outboundCount() else: 0

  # Build networks array
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
      "limited": true,
      "reachable": false,
      "proxy": "",
      "proxy_randomize_credentials": false
    },
    {
      "name": "onion",
      "limited": true,
      "reachable": false,
      "proxy": "",
      "proxy_randomize_credentials": false
    }
  ]

  %*{
    "version": 210000,
    "subversion": "/nimrod:0.1.0/",
    "protocolversion": 70016,
    "localservices": "0000000000000409",
    "localservicesnames": ["NETWORK", "WITNESS", "NETWORK_LIMITED"],
    "localrelay": true,
    "timeoffset": 0,
    "networkactive": true,
    "connections": connCount,
    "connections_in": inCount,
    "connections_out": outCount,
    "networks": networks,
    "relayfee": 0.00001,
    "incrementalfee": 0.00001,
    "localaddresses": [],
    "warnings": ""
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

      peers.add(%*{
        "id": id,
        "addr": peer.address & ":" & $peer.port,
        "services": servicesHex,
        "servicesnames": servicesNames,
        "relaytxes": true,
        "lastsend": peer.lastSeen.toUnix(),
        "lastrecv": peer.lastSeen.toUnix(),
        "last_transaction": 0,
        "last_block": 0,
        "bytessent": 0,
        "bytesrecv": 0,
        "conntime": connTime,
        "timeoffset": 0,
        "pingtime": pingTime,
        "minping": pingTime,
        "version": peer.version,
        "subver": peer.userAgent,
        "inbound": peer.direction == pdInbound,
        "bip152_hb_to": false,
        "bip152_hb_from": false,
        "startingheight": peer.startHeight,
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
        "session_id": ""
      })
      inc id

  peers

proc handleGetConnectionCount(rpc: RpcServer): JsonNode =
  if rpc.peerManager != nil:
    %rpc.peerManager.connectedPeerCount()
  else:
    %0

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
    discard await pm.connectToPeer(h, p)

  case command
  of "add":
    asyncSpawn connectAsync(rpc.peerManager, host, port)
  of "remove":
    for peer in rpc.peerManager.getReadyPeers():
      if peer.address == host and peer.port == port:
        asyncSpawn rpc.peerManager.removePeer(peer)
        break
  of "onetry":
    asyncSpawn connectAsync(rpc.peerManager, host, port)
  else:
    raise newRpcError(RpcInvalidParams, "invalid command: " & command)

  newJNull()

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

  %*{
    "capabilities": ["proposal"],
    "version": tmpl.header.version,
    "rules": ["csv", "segwit"],
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

proc handleSubmitBlock(rpc: RpcServer, params: JsonNode): JsonNode =
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing hexdata parameter")

  let blockHex = params[0].getStr()

  try:
    let blockBytes = hexToBytes(blockHex)
    let blk = deserializeBlock(blockBytes)

    # Validate the block
    let checkResult = checkBlock(blk, rpc.params)
    if not checkResult.isOk:
      return %($checkResult.error)

    # Connect to chainstate
    var cs = rpc.chainState
    let height = cs.bestHeight + 1
    let connectResult = cs.connectBlock(blk, height)

    if not connectResult.isOk:
      return %(connectResult.error)

    # Remove confirmed transactions from mempool
    var mp = rpc.mempool
    mp.removeForBlock(blk)

    # Update fee estimator
    if rpc.feeEstimator != nil:
      var confirmedTxids: seq[TxId]
      for tx in blk.txs:
        confirmedTxids.add(tx.txid())
      rpc.feeEstimator.processBlock(height, confirmedTxids)

    # Broadcast to peers
    if rpc.peerManager != nil:
      asyncSpawn rpc.peerManager.broadcastBlock(blk)

    newJNull()  # Success
  except CatchableError as e:
    %(e.msg)

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

  var feeRate: float64
  if rpc.feeEstimator != nil:
    feeRate = rpc.feeEstimator.estimateFee(confTarget)
  else:
    feeRate = FallbackFeeRate

  # Convert sat/vbyte to BTC/kB
  let feeBtcPerKb = feeRate * 1000.0 / 100000000.0

  %*{
    "feerate": feeBtcPerKb,
    "blocks": confTarget
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

proc handleSetBan(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Add or remove a peer from the ban list
  ## setban "address" "add|remove" [bantime] [absolute]
  if params.len < 2:
    raise newRpcError(RpcInvalidParams, "missing required parameters: address, command")

  if rpc.peerManager == nil:
    raise newRpcError(RpcInternalError, "peer manager not available")

  let address = params[0].getStr()
  let command = params[1].getStr()

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

proc handleValidateAddress(rpc: RpcServer, params: JsonNode): JsonNode =
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing address parameter")

  let addrStr = params[0].getStr()

  try:
    let parsedAddr = decodeAddress(addrStr)
    let isMain = isMainnet(addrStr)

    var addrType: string
    case parsedAddr.kind
    of P2PKH: addrType = "pubkeyhash"
    of P2SH: addrType = "scripthash"
    of P2WPKH: addrType = "witness_v0_keyhash"
    of P2WSH: addrType = "witness_v0_scripthash"
    of P2TR: addrType = "witness_v1_taproot"

    let scriptPubKey = scriptPubKeyForAddress(parsedAddr)

    %*{
      "isvalid": true,
      "address": addrStr,
      "scriptPubKey": toHex(scriptPubKey),
      "isscript": parsedAddr.kind == P2SH or parsedAddr.kind == P2WSH,
      "iswitness": parsedAddr.kind in {P2WPKH, P2WSH, P2TR},
      "witness_version": (if parsedAddr.kind == P2TR: 1 elif parsedAddr.kind in {P2WPKH, P2WSH}: 0 else: -1),
      "address_type": addrType
    }
  except AddressError:
    %*{
      "isvalid": false,
      "address": addrStr
    }

# ============================================================================
# Pruning RPCs
# ============================================================================

proc handlePruneBlockchain(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Prune the blockchain up to a specified height
  ## Reference: Bitcoin Core rpc/blockchain.cpp pruneblockchain
  ##
  ## Arguments:
  ## 1. height (numeric, required) - The block height to prune up to
  ##
  ## Returns:
  ## The height of the last block pruned
  ##
  ## Note: Pruning requires -prune option to be enabled

  if rpc.blockFileManager == nil:
    raise newRpcError(RpcMiscError, "pruning is not enabled")

  if not rpc.blockFileManager.isPruneMode:
    raise newRpcError(RpcMiscError, "cannot prune blocks because node is not in prune mode")

  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing height parameter")

  let targetHeight = params[0].getInt()
  let chainHeight = rpc.chainState.bestHeight

  if targetHeight < 0:
    raise newRpcError(RpcInvalidParams, "height must be non-negative")

  if targetHeight > chainHeight - MinBlocksToKeep:
    raise newRpcError(RpcInvalidParams,
      "Blockchain is shorter than the target height - " & $MinBlocksToKeep & " blocks")

  # Helper to get block hashes in a file
  proc getBlockHashesInFile(fileNum: int32): seq[BlockHash] =
    result = @[]
    # Iterate through known heights and find blocks in this file
    # This is a simplified approach - in production we'd use an index
    let infoOpt = rpc.blockFileManager.loadFileInfo(fileNum)
    if infoOpt.isSome:
      let info = infoOpt.get()
      for height in int32(info.nHeightFirst) .. int32(info.nHeightLast):
        let hashOpt = rpc.chainState.db.getBlockHashByHeight(height)
        if hashOpt.isSome:
          let entry = rpc.blockFileManager.getBlockIndex(hashOpt.get())
          if entry.isSome and entry.get().fileNum == fileNum:
            result.add(hashOpt.get())

  let (filesToPrune, prunedCount) = rpc.blockFileManager.findFilesToPruneManual(
    int32(targetHeight),
    chainHeight,
    getBlockHashesInFile
  )

  # Delete the pruned files
  rpc.blockFileManager.unlinkPrunedFiles(filesToPrune)

  # Return the last pruned height
  let pruneHeight = rpc.blockFileManager.getPruneHeight()
  %pruneHeight

# ============================================================================
# assumeUTXO / Snapshot RPCs
# ============================================================================

proc handleDumpTxOutSet(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Dump the UTXO set to a file
  ## Reference: Bitcoin Core rpc/blockchain.cpp dumptxoutset
  ##
  ## Arguments:
  ## 1. path (string, required) - Path to the output file
  ##
  ## Returns:
  ## {
  ##   "coins_written": n,      (numeric) Number of coins written
  ##   "base_hash": "...",      (string) Block hash at which snapshot was taken
  ##   "base_height": n,        (numeric) Block height at which snapshot was taken
  ##   "path": "...",           (string) Full path to the output file
  ##   "txoutset_hash": "..."   (string) SHA256d hash of the serialized UTXO set
  ## }

  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing path parameter")

  let path = params[0].getStr()
  if path == "":
    raise newRpcError(RpcInvalidParams, "path cannot be empty")

  # dumptxoutset not implemented (requires snapshot module)
  raise newRpcError(RpcInternalError, "dumptxoutset not implemented")

proc handleLoadTxOutSet(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Load a UTXO snapshot from a file
  ## Reference: Bitcoin Core rpc/blockchain.cpp loadtxoutset
  ##
  ## Arguments:
  ## 1. path (string, required) - Path to the snapshot file
  ##
  ## Returns:
  ## {
  ##   "coins_loaded": n,       (numeric) Number of coins loaded
  ##   "tip_hash": "...",       (string) Block hash at snapshot tip
  ##   "base_height": n,        (numeric) Block height of snapshot
  ##   "path": "..."            (string) Full path to the snapshot file
  ## }
  ##
  ## Note: The snapshot must match a known assumeUTXO hash in chainparams.
  ## After loading, background validation will verify the snapshot.

  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing path parameter")

  let path = params[0].getStr()
  if path == "":
    raise newRpcError(RpcInvalidParams, "path cannot be empty")

  # loadtxoutset not implemented (requires snapshot module)
  raise newRpcError(RpcInternalError, "loadtxoutset not implemented")

proc handleGetTxOutSetInfo(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Return statistics about the UTXO set
  ## Reference: Bitcoin Core rpc/blockchain.cpp gettxoutsetinfo
  ##
  ## Arguments:
  ## 1. hash_type (string, optional, default="hash_serialized_3") - Type of hash to compute
  ##
  ## Returns:
  ## {
  ##   "height": n,             (numeric) Current block height
  ##   "bestblock": "...",      (string) Best block hash
  ##   "txouts": n,             (numeric) Number of UTXOs (approximate from cache)
  ##   "bogosize": n,           (numeric) Estimated size of UTXO set data
  ##   "hash_serialized_3": "..." (string) SHA256d hash of UTXO set (if requested)
  ## }

  let hashType = if params.len >= 1: params[0].getStr() else: "hash_serialized_3"

  var response = %*{
    "height": rpc.chainState.bestHeight,
    "bestblock": reverseHex(toHex(array[32, byte](rpc.chainState.bestBlockHash))),
    "txouts": rpc.chainState.cacheSize,
    "bogosize": rpc.chainState.cacheSize * 50  # Rough estimate: ~50 bytes per UTXO
  }

  # Compute UTXO hash if requested (requires snapshot module)
  if hashType == "hash_serialized_3" or hashType == "hash_serialized":
    response["hash_serialized_3"] = %"not implemented"

  response

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

  if params.len >= 7 and params[6].kind == JBool:
    options.loadOnStartup = params[6].getBool()

  try:
    let (lw, warnings) = rpc.walletManager.createWallet(walletName, options)
    var result = %*{
      "name": lw.name,
      "warning": if warnings.len > 0: warnings.join("; ") else: ""
    }
    result
  except WalletManagerError as e:
    raise newRpcError(RpcMiscError, e.msg)
  except CatchableError as e:
    raise newRpcError(RpcMiscError, "Failed to create wallet: " & e.msg)

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

  # Parse address type (default to bech32/P2WPKH)
  var addressType = "bech32"
  if params.len >= 2 and params[1].kind == JString:
    addressType = params[1].getStr()

  try:
    let addrStr = w.getNewAddressByTypeName(addressType)
    %addrStr
  except WalletError as e:
    raise newRpcError(RpcMiscError, e.msg)

proc handleGetRawChangeAddress(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Generate a new change address
  ## Reference: Bitcoin Core wallet/rpc/addresses.cpp getrawchangeaddress
  ##
  ## Arguments:
  ## 1. address_type (string, optional) - Address type: "legacy", "p2sh-segwit", "bech32", "bech32m"
  ##
  ## Returns: New change address string

  var w = rpc.getTargetWallet()

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
    %addrStr
  except WalletError as e:
    raise newRpcError(RpcMiscError, e.msg)

proc handleGetBalance(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Get wallet balance
  ## Reference: Bitcoin Core wallet/rpc/coins.cpp getbalance

  let w = rpc.getTargetWallet()
  let balance = w.getBalance()
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
      var entry = %*{
        "txid": reverseHex(toHex(array[32, byte](utxo.outpoint.txid))),
        "vout": utxo.outpoint.vout,
        "amount": float64(int64(utxo.output.value)) / 100_000_000.0,
        "confirmations": confs,
        "scriptPubKey": toHex(utxo.output.scriptPubKey),
        "spendable": true,
        "solvable": true,
        "safe": true
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

  %*{
    "walletname": walletName,
    "walletversion": 1,
    "format": "nimrod",
    "balance": float64(int64(balance)) / 100_000_000.0,
    "unconfirmed_balance": 0.0,
    "immature_balance": float64(int64(immatureBalance)) / 100_000_000.0,
    "txcount": txCount,
    "keypoolsize": 20,
    "keypoolsize_hd_internal": 20,
    "paytxfee": 0.0,
    "private_keys_enabled": true,
    "avoid_reuse": false,
    "scanning": false,
    "descriptors": false,
    "external_signer": false,
    "unlocked_until": (if w.isEncrypted and not w.isLocked: w.unlockExpiry else: 0)
  }

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

  # Broadcast to peers
  if rpc.peerManager != nil:
    asyncSpawn rpc.peerManager.broadcastTx(tx)

  %txidHex

proc handleListTransactions(rpc: RpcServer, params: JsonNode): JsonNode =
  ## List wallet transactions
  ## Reference: Bitcoin Core wallet/rpc/transactions.cpp listtransactions
  ##
  ## Arguments:
  ## 1. label (string, optional, default="*") - Filter by label (or "*" for all)
  ## 2. count (numeric, optional, default=10) - Number of transactions to return
  ## 3. skip (numeric, optional, default=0) - Number of transactions to skip
  ## 4. include_watchonly (bool, optional, default=true) - Include watch-only addresses
  ##
  ## Returns: Array of transaction records
  ##
  ## Each entry:
  ## {
  ##   "address": "...",        - Address involved
  ##   "category": "...",       - "send", "receive", or "generate"
  ##   "amount": n,             - Amount in BTC
  ##   "vout": n,               - Output index
  ##   "fee": n,                - Fee (for "send" only)
  ##   "confirmations": n,      - Number of confirmations
  ##   "blockhash": "...",      - Block hash (if confirmed)
  ##   "blockheight": n,        - Block height (if confirmed)
  ##   "blockindex": n,         - Index in block (if confirmed)
  ##   "txid": "...",           - Transaction ID
  ##   "time": n,               - Transaction time
  ##   "timereceived": n        - Time received by wallet
  ## }

  let w = rpc.getTargetWallet()

  # Parse parameters
  let labelFilter = if params.len >= 1 and params[0].kind == JString: params[0].getStr() else: "*"
  let count = if params.len >= 2: params[1].getInt() else: 10
  let skip = if params.len >= 3: params[2].getInt() else: 0

  if count < 0:
    raise newRpcError(RpcInvalidParams, "count must be non-negative")
  if skip < 0:
    raise newRpcError(RpcInvalidParams, "skip must be non-negative")

  let currentHeight = if rpc.chainState != nil: rpc.chainState.bestHeight else: 0'i32
  let mainnet = rpc.params.network == Mainnet
  let now = getTime().toUnix()

  # Build transaction records from UTXOs
  # Each UTXO represents a "receive" transaction
  type TxRecord = object
    address: string
    category: string
    amount: float64
    vout: uint32
    confirmations: int32
    blockhash: string
    blockheight: int32
    txid: string
    time: int64
    timereceived: int64
    isCoinbase: bool

  var records: seq[TxRecord]

  for _, utxo in w.utxos:
    let confs = if utxo.height > 0: currentHeight - utxo.height + 1 else: 0'i32

    # Extract address from scriptPubKey
    let addrOpt = extractAddressFromScript(utxo.output.scriptPubKey, mainnet)
    let addressStr = if addrOpt.isSome: addrOpt.get() else: ""

    # Check label filter
    if labelFilter != "*":
      if addressStr != "":
        let label = w.labels.getOrDefault(addressStr, "")
        if label != labelFilter:
          continue
      else:
        continue

    # Determine category
    let category = if utxo.isCoinbase: "generate" else: "receive"

    # Get block hash if confirmed
    var blockhash = ""
    if utxo.height > 0:
      let bhOpt = rpc.chainState.db.getBlockHashByHeight(utxo.height)
      if bhOpt.isSome:
        blockhash = reverseHex(toHex(array[32, byte](bhOpt.get())))

    records.add(TxRecord(
      address: addressStr,
      category: category,
      amount: float64(int64(utxo.output.value)) / 100_000_000.0,
      vout: utxo.outpoint.vout,
      confirmations: confs,
      blockhash: blockhash,
      blockheight: utxo.height,
      txid: reverseHex(toHex(array[32, byte](utxo.outpoint.txid))),
      time: now,  # Simplified: real impl would track actual tx time
      timereceived: now,
      isCoinbase: utxo.isCoinbase
    ))

  # Sort by confirmations ascending (most recent first)
  records.sort(proc(a, b: TxRecord): int = cmp(a.confirmations, b.confirmations))

  # Apply skip and count
  var resultArray = newJArray()
  var added = 0
  var skipped = 0

  for record in records:
    if skipped < skip:
      inc skipped
      continue

    if added >= count:
      break

    var entry = %*{
      "address": record.address,
      "category": record.category,
      "amount": record.amount,
      "vout": record.vout,
      "confirmations": record.confirmations,
      "txid": record.txid,
      "time": record.time,
      "timereceived": record.timereceived
    }

    if record.blockhash != "":
      entry["blockhash"] = %record.blockhash
      entry["blockheight"] = %record.blockheight
      entry["blockindex"] = %0  # Simplified: index in block not tracked

    resultArray.add(entry)
    inc added

  resultArray

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

  try:
    let info = getDescriptorInfo(descriptorStr)
    %*{
      "descriptor": info.descriptor,
      "checksum": info.checksum,
      "isrange": info.isRange,
      "issolvable": info.isSolvable,
      "hasprivatekeys": info.hasPrivateKeys
    }
  except DescriptorError as e:
    raise newRpcError(RpcInvalidParams, "invalid descriptor: " & e.msg)

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

proc handleImportDescriptors(rpc: RpcServer, params: JsonNode): JsonNode =
  ## Import descriptors into the wallet
  ## Reference: Bitcoin Core wallet/rpc/backup.cpp importdescriptors
  ##
  ## Arguments:
  ## 1. requests (array, required) - Array of import requests
  ##
  ## Returns: Array of results

  if rpc.wallet == nil:
    raise newRpcError(RpcMiscError, "wallet not loaded")

  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing requests parameter")

  if params[0].kind != JArray:
    raise newRpcError(RpcInvalidParams, "requests must be an array")

  var results = newJArray()

  for request in params[0]:
    var result = %*{"success": false}

    try:
      if not request.hasKey("desc"):
        result["error"] = %*{"code": RpcInvalidParams, "message": "missing 'desc' field"}
        results.add(result)
        continue

      let descriptorStr = request["desc"].getStr()
      let timestamp = if request.hasKey("timestamp"): request["timestamp"] else: %"now"
      let rangeParam = if request.hasKey("range"): request["range"] else: newJNull()
      let internal = if request.hasKey("internal"): request["internal"].getBool() else: false
      let watchonly = if request.hasKey("watchonly"): request["watchonly"].getBool() else: true
      let label = if request.hasKey("label"): request["label"].getStr() else: ""

      # Parse and validate the descriptor
      let desc = parseDescriptor(descriptorStr)
      let info = getDescriptorInfo(descriptorStr)

      # For now, just validate and return success
      # Full implementation would add to wallet's watched descriptors
      result["success"] = %true
      result["warnings"] = %*[]

    except DescriptorError as e:
      result["error"] = %*{"code": RpcInvalidParams, "message": e.msg}
    except CatchableError as e:
      result["error"] = %*{"code": RpcInternalError, "message": e.msg}

    results.add(result)

  results

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

  # Parse inputs
  if params[0].kind != JArray:
    raise newRpcError(RpcInvalidParams, "inputs must be an array")

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

    # Default sequence: 0xffffffff unless replaceable or locktime set
    var sequence = 0xffffffff'u32
    if inputObj.hasKey("sequence"):
      sequence = uint32(inputObj["sequence"].getInt())

    txInputs.add(TxIn(
      prevOut: OutPoint(txid: txid, vout: vout),
      scriptSig: @[],  # Empty for PSBT
      sequence: sequence
    ))

  # Parse outputs
  if params[1].kind != JArray:
    raise newRpcError(RpcInvalidParams, "outputs must be an array")

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

  # Parse locktime
  var locktime = 0'u32
  if params.len >= 3 and params[2].kind != JNull:
    locktime = uint32(params[2].getInt())

  # Parse replaceable flag
  var replaceable = false
  if params.len >= 4 and params[3].kind != JNull:
    replaceable = params[3].getBool()

  # Apply RBF if replaceable or locktime > 0
  if replaceable or locktime > 0:
    for i in 0 ..< txInputs.len:
      if txInputs[i].sequence == 0xffffffff'u32:
        txInputs[i].sequence = 0xfffffffd'u32  # RBF-able sequence

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
    if inp.nonWitnessUtxo.isSome:
      let prevTx = inp.nonWitnessUtxo.get()
      inputObj["non_witness_utxo"] = %*{
        "txid": reverseHex(toHex(array[32, byte](prevTx.txid()))),
        "version": prevTx.version,
        "size": serialize(prevTx).len,
        "locktime": prevTx.lockTime
      }
      # Get the specific output value
      if psbtObj.tx.isSome:
        let outpoint = psbtObj.tx.get().inputs[i].prevOut
        if int(outpoint.vout) < prevTx.outputs.len:
          totalInputValue = totalInputValue + prevTx.outputs[outpoint.vout].value
        else:
          hasAllUtxos = false
      else:
        hasAllUtxos = false

    if inp.witnessUtxo.isSome:
      let utxo = inp.witnessUtxo.get()
      inputObj["witness_utxo"] = %*{
        "amount": float64(int64(utxo.value)) / 100_000_000.0,
        "scriptPubKey": buildScriptPubKeyJson(utxo.scriptPubKey, mainnet)
      }
      totalInputValue = totalInputValue + utxo.value
    elif inp.nonWitnessUtxo.isNone:
      hasAllUtxos = false

    # Partial signatures
    if inp.partialSigs.len > 0:
      var sigsObj = newJObject()
      for pubkey, sig in inp.partialSigs:
        sigsObj[toHex(pubkey)] = %toHex(sig)
      inputObj["partial_signatures"] = sigsObj

    # Sighash type
    if inp.sighashType.isSome:
      inputObj["sighash"] = %($inp.sighashType.get())

    # Scripts
    if inp.redeemScript.len > 0:
      inputObj["redeem_script"] = %*{
        "asm": disassembleScript(inp.redeemScript),
        "hex": toHex(inp.redeemScript)
      }

    if inp.witnessScript.len > 0:
      inputObj["witness_script"] = %*{
        "asm": disassembleScript(inp.witnessScript),
        "hex": toHex(inp.witnessScript)
      }

    # BIP32 derivation paths
    if inp.hdKeypaths.len > 0:
      var derivsArray = newJArray()
      for pubkey, origin in inp.hdKeypaths:
        var pathStr = "m"
        for idx in origin.path:
          if (idx and 0x80000000'u32) != 0:
            pathStr.add("/" & $(idx and 0x7fffffff'u32) & "'")
          else:
            pathStr.add("/" & $idx)
        derivsArray.add(%*{
          "pubkey": toHex(pubkey),
          "master_fingerprint": toHex(origin.fingerprint),
          "path": pathStr
        })
      inputObj["bip32_derivs"] = derivsArray

    # Final scripts
    if inp.finalScriptSig.len > 0:
      inputObj["final_scriptSig"] = %*{
        "asm": disassembleScript(inp.finalScriptSig),
        "hex": toHex(inp.finalScriptSig)
      }

    if inp.finalScriptWitness.len > 0:
      var witnessArray = newJArray()
      for item in inp.finalScriptWitness:
        witnessArray.add(%toHex(item))
      inputObj["final_scriptwitness"] = witnessArray

    # Taproot fields
    if inp.tapKeySig.len > 0:
      inputObj["tap_key_sig"] = %toHex(inp.tapKeySig)

    if inp.tapInternalKey != default(array[32, byte]):
      inputObj["tap_internal_key"] = %toHex(inp.tapInternalKey)

    if inp.tapMerkleRoot != default(array[32, byte]):
      inputObj["tap_merkle_root"] = %toHex(inp.tapMerkleRoot)

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
            pathStr.add("/" & $(idx and 0x7fffffff'u32) & "'")
          else:
            pathStr.add("/" & $idx)
        derivsArray.add(%*{
          "pubkey": toHex(pubkey),
          "master_fingerprint": toHex(origin.fingerprint),
          "path": pathStr
        })
      outputObj["bip32_derivs"] = derivsArray

    if outp.tapInternalKey != default(array[32, byte]):
      outputObj["tap_internal_key"] = %toHex(outp.tapInternalKey)

    outputsArray.add(outputObj)

  # Calculate fee if we have all UTXOs
  var feeNode = newJNull()
  if hasAllUtxos and psbtObj.tx.isSome:
    var totalOutput = Satoshi(0)
    for outp in psbtObj.tx.get().outputs:
      totalOutput = totalOutput + outp.value
    if int64(totalInputValue) >= int64(totalOutput):
      let fee = totalInputValue - totalOutput
      feeNode = %(float64(int64(fee)) / 100_000_000.0)

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

proc handleMethod(rpc: RpcServer, methodName: string, params: JsonNode): JsonNode =
  case methodName
  # Blockchain
  of "getblockchaininfo":
    rpc.handleGetBlockchainInfo()
  of "getblockcount":
    rpc.handleGetBlockCount()
  of "getbestblockhash":
    rpc.handleGetBestBlockHash()
  of "getblockhash":
    rpc.handleGetBlockHash(params)
  of "getblockheader":
    rpc.handleGetBlockHeader(params)
  of "getblock":
    rpc.handleGetBlock(params)
  of "getdifficulty":
    rpc.handleGetDifficulty()
  of "getchaintips":
    rpc.handleGetChainTips()
  of "pruneblockchain":
    rpc.handlePruneBlockchain(params)

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

  # Mempool
  of "getmempoolinfo":
    rpc.handleGetMempoolInfo()
  of "getrawmempool":
    rpc.handleGetRawMempool(params)
  of "getmempoolentry":
    rpc.handleGetMempoolEntry(params)

  # Raw transactions
  of "getrawtransaction":
    rpc.handleGetRawTransaction(params)
  of "decoderawtransaction":
    rpc.handleDecodeRawTransaction(params)
  of "sendrawtransaction":
    rpc.handleSendRawTransaction(params)
  of "submitpackage":
    rpc.handleSubmitPackage(params)

  # Network
  of "getnetworkinfo":
    rpc.handleGetNetworkInfo()
  of "getpeerinfo":
    rpc.handleGetPeerInfo()
  of "getconnectioncount":
    rpc.handleGetConnectionCount()
  of "addnode":
    rpc.handleAddNode(params)
  of "listbanned":
    rpc.handleListBanned()
  of "setban":
    rpc.handleSetBan(params)
  of "clearbanned":
    rpc.handleClearBanned()

  # ZMQ
  of "getzmqnotifications":
    rpc.handleGetZmqNotifications()

  # Mining
  of "getblocktemplate":
    rpc.handleGetBlockTemplate(params)
  of "submitblock":
    rpc.handleSubmitBlock(params)

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

  # Utility
  of "validateaddress":
    rpc.handleValidateAddress(params)

  # Wallet
  of "getnewaddress":
    rpc.handleGetNewAddress(params)
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

  # Descriptors
  of "getdescriptorinfo":
    rpc.handleGetDescriptorInfo(params)
  of "deriveaddresses":
    rpc.handleDeriveAddresses(params)
  of "importdescriptors":
    rpc.handleImportDescriptors(params)

  # PSBT
  of "createpsbt":
    rpc.handleCreatePsbt(params)
  of "decodepsbt":
    rpc.handleDecodePsbt(params)
  of "combinepsbt":
    rpc.handleCombinePsbt(params)
  of "finalizepsbt":
    rpc.handleFinalizePsbt(params)

  # Control
  of "stop":
    # Return success - actual shutdown handled by caller
    %"nimrod server stopping"

  else:
    raise newRpcError(RpcMethodNotFound, "method not found: " & methodName)

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

proc handleRequest(rpc: RpcServer, body: string): string =
  ## Handle a JSON-RPC request (single or batch)
  ## Reference: Bitcoin Core httprpc.cpp HTTPReq_JSONRPC
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

proc checkAuth(rpc: RpcServer, authHeader: string): bool =
  ## Verify HTTP Basic auth credentials
  if rpc.authUser == "" and rpc.authPass == "":
    return true  # No auth configured

  if not authHeader.startsWith("Basic "):
    return false

  try:
    let decoded = decode(authHeader[6 .. ^1])
    let parts = decoded.split(':')
    if parts.len != 2:
      return false
    return parts[0] == rpc.authUser and parts[1] == rpc.authPass
  except CatchableError:
    return false

proc processClient(rpc: RpcServer, transp: StreamTransport) {.async.} =
  ## Handle a single client connection with proper HTTP parsing
  var headers: Table[string, string]
  var contentLength = 0
  var inHeaders = true
  var authHeader = ""

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

            var respResult: string
            {.gcsafe.}:
              try:
                respResult = rpc.handleRequest(body)
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

        elif line.startsWith("POST") or line.startsWith("GET"):
          # Request line - ignore
          discard

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
