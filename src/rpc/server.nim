## JSON-RPC server
## Bitcoin Core compatible RPC interface with HTTP Basic auth
## JSON-RPC 2.0 compliant with proper error codes

import std/[json, strutils, tables, options, base64, parseutils, times]
import chronos
import chronicles
import jsony
import ../primitives/[types, serialize]
import ../consensus/[params, validation]
import ../storage/chainstate
import ../mempool/mempool
import ../crypto/[hashing, secp256k1, address]
import ../network/[peer, peermanager, banman]
import ../mining/[fees, blocktemplate]

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
  RpcTransactionError* = -25       # Generic transaction error
  RpcTransactionRejected* = -26    # Transaction rejected by mempool
  RpcTransactionAlreadyInChain* = -27  # Transaction already confirmed

  # Default maxfeerate: 0.10 BTC/kvB = 10,000,000 sat/kvB = 10,000 sat/vB
  DefaultMaxFeeRate* = 0.10  # BTC/kvB

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
  let target = bitsToTarget(rpc.params.genesisBits)
  %*{
    "chain": (if rpc.params.network == Mainnet: "main"
              elif rpc.params.network == Testnet3: "test"
              else: "regtest"),
    "blocks": rpc.chainState.bestHeight,
    "headers": rpc.chainState.bestHeight,
    "bestblockhash": reverseHex(toHex(array[32, byte](rpc.chainState.bestBlockHash))),
    "difficulty": targetToDifficulty(target),
    "mediantime": 0,
    "verificationprogress": 1.0,
    "initialblockdownload": rpc.chainState.bestHeight < 100,
    "chainwork": toHex(rpc.chainState.totalWork),
    "size_on_disk": 0,
    "pruned": false
  }

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
        "ancestorfees": int64(entry.ancestorFee)
      }
    return entries
  else:
    var txids: seq[string]
    for txid in rpc.mempool.entries.keys:
      txids.add(reverseHex(toHex(array[32, byte](txid))))
    return %txids

# Raw transaction RPCs
proc handleGetRawTransaction(rpc: RpcServer, params: JsonNode): JsonNode =
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing txid parameter")

  let txidHex = params[0].getStr()
  let verbose = if params.len >= 2: params[1].getBool() else: false

  let txid = parseTxId(txidHex)

  # Check mempool first
  let mempoolTx = rpc.mempool.getTransaction(txid)
  if mempoolTx.isSome:
    let tx = mempoolTx.get()
    if not verbose:
      return %toHex(serialize(tx))

    let entry = rpc.mempool.get(txid)
    let vsize = (entry.get().weight + 3) div 4

    return %*{
      "txid": reverseHex(toHex(array[32, byte](txid))),
      "hash": reverseHex(toHex(array[32, byte](tx.wtxid()))),
      "version": tx.version,
      "size": serialize(tx).len,
      "vsize": vsize,
      "weight": entry.get().weight,
      "locktime": tx.lockTime,
      "hex": toHex(serialize(tx))
    }

  # Check tx index
  let locOpt = rpc.chainState.db.getTxIndex(txid)
  if locOpt.isNone:
    raise newRpcError(RpcInvalidParams, "transaction not found")

  let loc = locOpt.get()
  let blkOpt = rpc.chainState.db.getBlock(loc.blockHash)
  if blkOpt.isNone:
    raise newRpcError(RpcInternalError, "block not found for indexed transaction")

  let blk = blkOpt.get()
  if int(loc.txIndex) >= blk.txs.len:
    raise newRpcError(RpcInternalError, "invalid tx index")

  let tx = blk.txs[loc.txIndex]

  if not verbose:
    return %toHex(serialize(tx))

  let idxOpt = rpc.chainState.db.getBlockIndex(loc.blockHash)
  let blockHeight = if idxOpt.isSome: idxOpt.get().height else: 0'i32

  %*{
    "txid": reverseHex(toHex(array[32, byte](txid))),
    "hash": reverseHex(toHex(array[32, byte](tx.wtxid()))),
    "version": tx.version,
    "size": serialize(tx).len,
    "vsize": (calculateTransactionWeight(tx) + 3) div 4,
    "weight": calculateTransactionWeight(tx),
    "locktime": tx.lockTime,
    "hex": toHex(serialize(tx)),
    "blockhash": reverseHex(toHex(array[32, byte](loc.blockHash))),
    "confirmations": rpc.chainState.bestHeight - blockHeight + 1,
    "time": blk.header.timestamp,
    "blocktime": blk.header.timestamp
  }

proc handleDecodeRawTransaction(rpc: RpcServer, params: JsonNode): JsonNode =
  if params.len < 1:
    raise newRpcError(RpcInvalidParams, "missing hexstring parameter")

  let txHex = params[0].getStr()

  try:
    let txBytes = hexToBytes(txHex)
    let tx = deserializeTransaction(txBytes)
    let txid = tx.txid()
    let wtxid = tx.wtxid()
    let weight = calculateTransactionWeight(tx)

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
    let weight = calculateTransactionWeight(tx)
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

# Network RPCs
proc handleGetNetworkInfo(rpc: RpcServer): JsonNode =
  let connCount = if rpc.peerManager != nil: rpc.peerManager.connectedPeerCount() else: 0
  let inCount = if rpc.peerManager != nil: rpc.peerManager.inboundCount() else: 0
  let outCount = if rpc.peerManager != nil: rpc.peerManager.outboundCount() else: 0

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
    "networks": [],
    "relayfee": 0.00001,
    "incrementalfee": 0.00001,
    "localaddresses": [],
    "warnings": ""
  }

proc handleGetPeerInfo(rpc: RpcServer): JsonNode =
  var peers = newJArray()

  if rpc.peerManager != nil:
    var id = 0
    for peer in rpc.peerManager.getReadyPeers():
      peers.add(%*{
        "id": id,
        "addr": peer.address & ":" & $peer.port,
        "services": "0000000000000409",
        "relaytxes": true,
        "lastsend": 0,
        "lastrecv": 0,
        "bytessent": 0,
        "bytesrecv": 0,
        "conntime": 0,
        "timeoffset": 0,
        "pingtime": 0,
        "version": peer.version,
        "subver": peer.userAgent,
        "inbound": peer.direction == pdInbound,
        "startingheight": peer.startHeight,
        "synced_headers": rpc.chainState.bestHeight,
        "synced_blocks": rpc.chainState.bestHeight
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
      "weight": calculateTransactionWeight(tx)
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

  # Mempool
  of "getmempoolinfo":
    rpc.handleGetMempoolInfo()
  of "getrawmempool":
    rpc.handleGetRawMempool(params)

  # Raw transactions
  of "getrawtransaction":
    rpc.handleGetRawTransaction(params)
  of "decoderawtransaction":
    rpc.handleDecodeRawTransaction(params)
  of "sendrawtransaction":
    rpc.handleSendRawTransaction(params)

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

  # Mining
  of "getblocktemplate":
    rpc.handleGetBlockTemplate(params)
  of "submitblock":
    rpc.handleSubmitBlock(params)

  # Fee estimation
  of "estimatesmartfee":
    rpc.handleEstimateSmartFee(params)

  # Utility
  of "validateaddress":
    rpc.handleValidateAddress(params)

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

proc handleRequest(rpc: RpcServer, body: string): string =
  var response: RpcResponse
  response.jsonrpc = "2.0"
  var requestId = newJNull()

  try:
    let request = body.fromJson(RpcRequest)
    requestId = request.id
    response.id = request.id
    response.result = rpc.handleMethod(request.`method`, request.params)
    response.error = newJNull()
  except RpcError as e:
    response.id = requestId
    response.error = %*{
      "code": e.code,
      "message": e.msg
    }
    response.result = newJNull()
  except json.JsonParsingError as e:
    return makeErrorResponse(requestId, RpcParseError, "parse error: " & e.msg)
  except CatchableError as e:
    response.id = requestId
    response.error = %*{
      "code": RpcInternalError,
      "message": "internal error: " & e.msg
    }
    response.result = newJNull()
  except Exception as e:
    # Catch jsony parse errors which inherit from Exception
    response.id = requestId
    response.error = %*{
      "code": RpcParseError,
      "message": "parse error: " & e.msg
    }
    response.result = newJNull()

  $ %*{
    "jsonrpc": response.jsonrpc,
    "id": response.id,
    "result": response.result,
    "error": response.error
  }

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

        if line.len == 0:
          # End of headers
          inHeaders = false

          # Check auth
          if not rpc.checkAuth(authHeader):
            let response = "HTTP/1.1 401 Unauthorized\r\n" &
                          "WWW-Authenticate: Basic realm=\"nimrod\"\r\n" &
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
                              "Content-Length: " & $respResult.len & "\r\n" &
                              "\r\n" & respResult
            discard await transp.write(httpResponse)

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
