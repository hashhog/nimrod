## JSON-RPC server
## Bitcoin Core compatible RPC interface

import std/[json, strutils, tables, options]
import chronos
import chronicles
import jsony
import ../primitives/[types, serialize]
import ../consensus/params
import ../storage/chainstate
import ../mempool/mempool
import ../crypto/hashing

type
  RpcError* = object of CatchableError

  RpcServer* = ref object
    port*: uint16
    chainState*: ChainState
    mempool*: Mempool
    params*: ConsensusParams
    running*: bool

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

proc newRpcServer*(
  port: uint16,
  chainState: ChainState,
  mempool: Mempool,
  params: ConsensusParams
): RpcServer =
  RpcServer(
    port: port,
    chainState: chainState,
    mempool: mempool,
    params: params,
    running: false
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

proc handleGetBlockchainInfo(rpc: RpcServer): JsonNode =
  %*{
    "chain": (if rpc.params.network == Mainnet: "main"
              elif rpc.params.network == Testnet3: "test"
              else: "regtest"),
    "blocks": rpc.chainState.bestHeight,
    "headers": rpc.chainState.bestHeight,
    "bestblockhash": reverseHex(toHex(array[32, byte](rpc.chainState.bestBlockHash))),
    "difficulty": 1.0,
    "mediantime": 0,
    "verificationprogress": 1.0,
    "initialblockdownload": false,
    "chainwork": "0",
    "size_on_disk": 0,
    "pruned": false
  }

proc handleGetBlockCount(rpc: RpcServer): JsonNode =
  %rpc.chainState.bestHeight

proc handleGetBestBlockHash(rpc: RpcServer): JsonNode =
  %reverseHex(toHex(array[32, byte](rpc.chainState.bestBlockHash)))

proc handleGetBlock(rpc: RpcServer, params: JsonNode): JsonNode =
  if params.len < 1:
    raise newException(RpcError, "missing blockhash parameter")

  let hashHex = params[0].getStr()
  var hashBytes: array[32, byte]
  let reversedHex = reverseHex(hashHex)
  for i in 0 ..< 32:
    hashBytes[i] = byte(parseHexInt(reversedHex[i*2 .. i*2 + 1]))

  let blk = rpc.chainState.getBlockByHash(BlockHash(hashBytes))
  if blk.isNone:
    raise newException(RpcError, "block not found")

  let b = blk.get()
  let headerBytes = serialize(b.header)
  let blockHash = doubleSha256(headerBytes)

  var txids: seq[string]
  for tx in b.transactions:
    let txBytes = serialize(tx)
    let txid = doubleSha256(txBytes)
    txids.add(reverseHex(toHex(txid)))

  %*{
    "hash": reverseHex(toHex(blockHash)),
    "confirmations": rpc.chainState.bestHeight - 0 + 1,  # Would need block height
    "size": serialize(b).len,
    "weight": serialize(b).len * 4,
    "height": 0,  # Would need to look up
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
    "difficulty": 1.0,
    "chainwork": "0",
    "nTx": b.transactions.len,
    "previousblockhash": reverseHex(toHex(array[32, byte](b.header.prevHash)))
  }

proc handleGetMempoolInfo(rpc: RpcServer): JsonNode =
  %*{
    "loaded": true,
    "size": rpc.mempool.count,
    "bytes": rpc.mempool.size,
    "usage": rpc.mempool.size,
    "maxmempool": rpc.mempool.maxSize,
    "mempoolminfee": 0.00001,
    "minrelaytxfee": 0.00001
  }

proc handleGetRawMempool(rpc: RpcServer): JsonNode =
  var txids: seq[string]
  for txid in rpc.mempool.entries.keys:
    txids.add(reverseHex(toHex(array[32, byte](txid))))
  %txids

proc handleGetNetworkInfo(rpc: RpcServer): JsonNode =
  %*{
    "version": 210000,
    "subversion": "/nimrod:0.1.0/",
    "protocolversion": 70016,
    "localservices": "0000000000000001",
    "localrelay": true,
    "timeoffset": 0,
    "networkactive": true,
    "connections": 0,
    "connections_in": 0,
    "connections_out": 0,
    "networks": [],
    "relayfee": 0.00001,
    "incrementalfee": 0.00001,
    "localaddresses": [],
    "warnings": ""
  }

proc handleMethod(rpc: RpcServer, methodName: string, params: JsonNode): JsonNode =
  case methodName
  of "getblockchaininfo":
    rpc.handleGetBlockchainInfo()
  of "getblockcount":
    rpc.handleGetBlockCount()
  of "getbestblockhash":
    rpc.handleGetBestBlockHash()
  of "getblock":
    rpc.handleGetBlock(params)
  of "getmempoolinfo":
    rpc.handleGetMempoolInfo()
  of "getrawmempool":
    rpc.handleGetRawMempool()
  of "getnetworkinfo":
    rpc.handleGetNetworkInfo()
  else:
    raise newException(RpcError, "method not found: " & methodName)

proc handleRequest(rpc: RpcServer, body: string): string =
  var response: RpcResponse
  response.jsonrpc = "2.0"

  try:
    let request = body.fromJson(RpcRequest)
    response.id = request.id
    response.result = rpc.handleMethod(request.`method`, request.params)
    response.error = newJNull()
  except RpcError as e:
    response.error = %*{
      "code": -32600,
      "message": e.msg
    }
    response.result = newJNull()
  except CatchableError as e:
    response.error = %*{
      "code": -32603,
      "message": "internal error: " & e.msg
    }
    response.result = newJNull()

  $ %*{
    "jsonrpc": response.jsonrpc,
    "id": response.id,
    "result": response.result,
    "error": response.error
  }

proc processClient(rpc: RpcServer, transp: StreamTransport) {.async.} =
  ## Handle a single client connection
  var buffer = ""

  while not transp.closed:
    try:
      var line = await transp.readLine()
      if line.len == 0:
        if buffer.len > 0:
          # Process complete request
          let response = rpc.handleRequest(buffer)
          let httpResponse = "HTTP/1.1 200 OK\r\n" &
                            "Content-Type: application/json\r\n" &
                            "Content-Length: " & $response.len & "\r\n" &
                            "\r\n" & response
          discard await transp.write(httpResponse)
          buffer = ""
        continue

      if line.startsWith("POST") or line.startsWith("GET"):
        buffer = ""
        continue

      if line.startsWith("Content-Length"):
        continue

      if not line.startsWith("HTTP") and not line.contains(":"):
        buffer.add(line)

    except CatchableError:
      break

  await transp.closeWait()

proc start*(rpc: RpcServer) {.async.} =
  ## Start the RPC server
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
