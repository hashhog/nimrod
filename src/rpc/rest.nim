## REST API server
## Read-only HTTP endpoints for blockchain queries
## Supports JSON, binary, and hex formats
## No authentication required (read-only)
##
## Reference: Bitcoin Core rest.cpp

import std/[json, strutils, tables, options, times]
import chronos
import chronicles
import ../primitives/[types, serialize]
import ../consensus/params
import ../consensus/validation as consensus_validation
import ../storage/[chainstate, blockstore]
import ../storage/indexes/txindex
import ../mempool/mempool
import ../crypto/hashing

type
  RestError* = object of CatchableError

  RestResponseFormat* = enum
    rfUndef = "undefined"
    rfBinary = "bin"
    rfHex = "hex"
    rfJson = "json"

  RestServer* = ref object
    port*: uint16
    chainState*: ChainState
    mempool*: Mempool
    params*: ConsensusParams
    running*: bool
    txIndex*: TxIndex  ## Optional: for tx lookup

const
  MaxGetUtxosOutpoints* = 15  ## Max outpoints per getutxos request
  MaxRestHeadersResults* = 2000  ## Max headers per request

proc newRestError(msg: string): ref RestError =
  newException(RestError, msg)

proc newRestServer*(
  port: uint16,
  chainState: ChainState,
  mempool: Mempool,
  params: ConsensusParams,
  txIndex: TxIndex = nil
): RestServer =
  RestServer(
    port: port,
    chainState: chainState,
    mempool: mempool,
    params: params,
    running: false,
    txIndex: txIndex
  )

# ============================================================================
# Utility functions
# ============================================================================

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
  if hex.len mod 2 != 0:
    raise newRestError("invalid hex length")
  result = newSeq[byte](hex.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(hex[i*2 .. i*2 + 1]))

proc parseBlockHash*(hashHex: string): BlockHash =
  if hashHex.len != 64:
    raise newRestError("invalid block hash length")
  var hashBytes: array[32, byte]
  let reversedHex = reverseHex(hashHex)
  for i in 0 ..< 32:
    hashBytes[i] = byte(parseHexInt(reversedHex[i*2 .. i*2 + 1]))
  BlockHash(hashBytes)

proc parseTxId*(txidHex: string): TxId =
  if txidHex.len != 64:
    raise newRestError("invalid txid length")
  var hashBytes: array[32, byte]
  let reversedHex = reverseHex(txidHex)
  for i in 0 ..< 32:
    hashBytes[i] = byte(parseHexInt(reversedHex[i*2 .. i*2 + 1]))
  TxId(hashBytes)

proc parseDataFormat*(param: var string, path: string): RestResponseFormat =
  ## Parse the data format from URL path
  ## Returns format and removes extension from param
  # Remove query string if present
  param = path.split('?')[0]

  let dotPos = param.rfind('.')
  if dotPos < 0:
    return rfUndef

  let suffix = param[dotPos + 1 .. ^1].toLowerAscii
  param = param[0 ..< dotPos]

  case suffix
  of "bin": rfBinary
  of "hex": rfHex
  of "json": rfJson
  else: rfUndef

proc availableFormatsString*(): string =
  ".bin, .hex, .json"

# ============================================================================
# Response helpers
# ============================================================================

type
  HttpStatusCode* = enum
    Http200 = "200 OK"
    Http400 = "400 Bad Request"
    Http404 = "404 Not Found"
    Http500 = "500 Internal Server Error"
    Http503 = "503 Service Unavailable"

  RestResponse* = object
    status*: HttpStatusCode
    contentType*: string
    body*: string

proc restOk*(body: string, contentType: string = "application/json"): RestResponse =
  RestResponse(status: Http200, contentType: contentType, body: body)

proc restError*(status: HttpStatusCode, message: string): RestResponse =
  RestResponse(status: status, contentType: "text/plain", body: message & "\r\n")

proc restBinary*(data: seq[byte]): RestResponse =
  RestResponse(status: Http200, contentType: "application/octet-stream",
               body: cast[string](data))

proc restHex*(data: seq[byte]): RestResponse =
  RestResponse(status: Http200, contentType: "text/plain",
               body: toHex(data) & "\n")

proc restJson*(data: JsonNode): RestResponse =
  RestResponse(status: Http200, contentType: "application/json",
               body: $data & "\n")

# ============================================================================
# Block endpoint handlers
# ============================================================================

proc handleRestBlock*(rest: RestServer, uriPart: string,
                      txDetails: bool = true): RestResponse =
  ## GET /rest/block/<hash>.<format>
  ## GET /rest/block/notxdetails/<hash>.<format>
  var hashStr = uriPart
  let rf = parseDataFormat(hashStr, uriPart)

  if rf == rfUndef:
    return restError(Http404, "output format not found (available: " & availableFormatsString() & ")")

  let blockHash = try:
    parseBlockHash(hashStr)
  except RestError as e:
    return restError(Http400, "Invalid hash: " & hashStr)
  except CatchableError:
    return restError(Http400, "Invalid hash: " & hashStr)

  # Get block from storage
  let blkOpt = rest.chainState.db.getBlock(blockHash)
  if blkOpt.isNone:
    return restError(Http404, hashStr & " not found")

  let blk = blkOpt.get()

  case rf
  of rfBinary:
    restBinary(serialize(blk))
  of rfHex:
    restHex(serialize(blk))
  of rfJson:
    # Get block index for height and confirmations
    let idxOpt = rest.chainState.db.getBlockIndex(blockHash)
    let height = if idxOpt.isSome: idxOpt.get().height else: 0'i32
    let confirmations = rest.chainState.bestHeight - height + 1

    var txArray = newJArray()
    for i, tx in blk.txs:
      if txDetails:
        # Full transaction details
        let txid = tx.txid()
        let wtxid = tx.wtxid()
        let weight = consensus_validation.calculateTransactionWeight(tx)

        var txObj = %*{
          "txid": reverseHex(toHex(array[32, byte](txid))),
          "hash": reverseHex(toHex(array[32, byte](wtxid))),
          "version": tx.version,
          "size": serialize(tx).len,
          "vsize": (weight + 3) div 4,
          "weight": weight,
          "locktime": tx.lockTime
        }

        # Add vin array
        var vinArray = newJArray()
        for j, inp in tx.inputs:
          let isCoinbase = inp.prevOut.txid == TxId(default(array[32, byte])) and
                           inp.prevOut.vout == 0xFFFFFFFF'u32
          if isCoinbase:
            vinArray.add(%*{"coinbase": toHex(inp.scriptSig), "sequence": inp.sequence})
          else:
            var vinObj = %*{
              "txid": reverseHex(toHex(array[32, byte](inp.prevOut.txid))),
              "vout": inp.prevOut.vout,
              "scriptSig": %*{"hex": toHex(inp.scriptSig)},
              "sequence": inp.sequence
            }
            if j < tx.witnesses.len and tx.witnesses[j].len > 0:
              var witArray = newJArray()
              for item in tx.witnesses[j]:
                witArray.add(%toHex(item))
              vinObj["txinwitness"] = witArray
            vinArray.add(vinObj)
        txObj["vin"] = vinArray

        # Add vout array
        var voutArray = newJArray()
        for k, outp in tx.outputs:
          voutArray.add(%*{
            "value": float64(int64(outp.value)) / 100_000_000.0,
            "n": k,
            "scriptPubKey": %*{"hex": toHex(outp.scriptPubKey)}
          })
        txObj["vout"] = voutArray

        txArray.add(txObj)
      else:
        # Just txid
        txArray.add(%reverseHex(toHex(array[32, byte](tx.txid()))))

    let blockJson = %*{
      "hash": reverseHex(toHex(array[32, byte](blockHash))),
      "confirmations": confirmations,
      "height": height,
      "version": blk.header.version,
      "merkleroot": reverseHex(toHex(blk.header.merkleRoot)),
      "time": blk.header.timestamp,
      "nonce": blk.header.nonce,
      "bits": toHex(cast[array[4, byte]]([
        byte(blk.header.bits and 0xff),
        byte((blk.header.bits shr 8) and 0xff),
        byte((blk.header.bits shr 16) and 0xff),
        byte((blk.header.bits shr 24) and 0xff)
      ])),
      "nTx": blk.txs.len,
      "tx": txArray
    }

    if height > 0:
      blockJson["previousblockhash"] = %reverseHex(toHex(array[32, byte](blk.header.prevBlock)))

    if height < rest.chainState.bestHeight:
      let nextHashOpt = rest.chainState.db.getBlockHashByHeight(height + 1)
      if nextHashOpt.isSome:
        blockJson["nextblockhash"] = %reverseHex(toHex(array[32, byte](nextHashOpt.get())))

    restJson(blockJson)
  else:
    restError(Http404, "output format not found")

proc handleRestBlockNoTxDetails*(rest: RestServer, uriPart: string): RestResponse =
  ## GET /rest/block/notxdetails/<hash>.<format>
  rest.handleRestBlock(uriPart, txDetails = false)

# ============================================================================
# Headers endpoint
# ============================================================================

proc handleRestHeaders*(rest: RestServer, uriPart: string): RestResponse =
  ## GET /rest/headers/<count>/<hash>.<format>
  var param = uriPart
  let rf = parseDataFormat(param, uriPart)

  if rf == rfUndef:
    return restError(Http404, "output format not found (available: " & availableFormatsString() & ")")

  let parts = param.split('/')
  if parts.len < 2:
    return restError(Http400, "Invalid URI format. Expected /rest/headers/<count>/<hash>")

  let countStr = parts[0]
  let hashStr = parts[1]

  let count = try:
    parseInt(countStr)
  except ValueError:
    return restError(Http400, "Invalid count: " & countStr)

  if count < 1 or count > MaxRestHeadersResults:
    return restError(Http400, "Header count out of range (1-" & $MaxRestHeadersResults & ")")

  let blockHash = try:
    parseBlockHash(hashStr)
  except CatchableError:
    return restError(Http400, "Invalid hash: " & hashStr)

  # Collect headers starting from hash
  var headers: seq[BlockHeader]
  let idxOpt = rest.chainState.db.getBlockIndex(blockHash)
  if idxOpt.isNone:
    return restError(Http404, hashStr & " not found")

  var currentHeight = idxOpt.get().height
  while headers.len < count and currentHeight <= rest.chainState.bestHeight:
    let hashOpt = rest.chainState.db.getBlockHashByHeight(currentHeight)
    if hashOpt.isNone:
      break

    # For the first header, verify it matches the requested hash
    if headers.len == 0 and hashOpt.get() != blockHash:
      break  # Requested hash is not on active chain

    let blkIdxOpt = rest.chainState.db.getBlockIndex(hashOpt.get())
    if blkIdxOpt.isSome:
      headers.add(blkIdxOpt.get().header)
    else:
      break

    inc currentHeight

  case rf
  of rfBinary:
    var data: seq[byte]
    for h in headers:
      data.add(serialize(h))
    restBinary(data)
  of rfHex:
    var data: seq[byte]
    for h in headers:
      data.add(serialize(h))
    restHex(data)
  of rfJson:
    var jsonHeaders = newJArray()
    for i, h in headers:
      let headerHash = doubleSha256(serialize(h))
      let headerIdx = rest.chainState.db.getBlockIndex(BlockHash(headerHash))
      let height = if headerIdx.isSome: headerIdx.get().height else: int32(idxOpt.get().height + int32(i))

      jsonHeaders.add(%*{
        "hash": reverseHex(toHex(headerHash)),
        "confirmations": rest.chainState.bestHeight - height + 1,
        "height": height,
        "version": h.version,
        "merkleroot": reverseHex(toHex(h.merkleRoot)),
        "time": h.timestamp,
        "nonce": h.nonce,
        "bits": toHex(cast[array[4, byte]]([
          byte(h.bits and 0xff),
          byte((h.bits shr 8) and 0xff),
          byte((h.bits shr 16) and 0xff),
          byte((h.bits shr 24) and 0xff)
        ])),
        "previousblockhash": reverseHex(toHex(array[32, byte](h.prevBlock)))
      })
    restJson(jsonHeaders)
  else:
    restError(Http404, "output format not found")

# ============================================================================
# Block hash by height endpoint
# ============================================================================

proc handleRestBlockHashByHeight*(rest: RestServer, uriPart: string): RestResponse =
  ## GET /rest/blockhashbyheight/<height>.<format>
  var heightStr = uriPart
  let rf = parseDataFormat(heightStr, uriPart)

  if rf == rfUndef:
    return restError(Http404, "output format not found (available: " & availableFormatsString() & ")")

  let height = try:
    parseInt(heightStr)
  except ValueError:
    return restError(Http400, "Invalid height: " & heightStr)

  if height < 0:
    return restError(Http400, "Invalid height: " & heightStr)

  if int32(height) > rest.chainState.bestHeight:
    return restError(Http404, "Block height out of range")

  let hashOpt = rest.chainState.db.getBlockHashByHeight(int32(height))
  if hashOpt.isNone:
    return restError(Http404, "Block height out of range")

  let blockHash = hashOpt.get()

  case rf
  of rfBinary:
    restBinary(@(array[32, byte](blockHash)))
  of rfHex:
    restOk(reverseHex(toHex(array[32, byte](blockHash))) & "\n", "text/plain")
  of rfJson:
    restJson(%*{"blockhash": reverseHex(toHex(array[32, byte](blockHash)))})
  else:
    restError(Http404, "output format not found")

# ============================================================================
# Transaction endpoint
# ============================================================================

proc handleRestTx*(rest: RestServer, uriPart: string): RestResponse =
  ## GET /rest/tx/<txid>.<format>
  ## Requires txindex to be enabled for confirmed transactions
  var txidStr = uriPart
  let rf = parseDataFormat(txidStr, uriPart)

  if rf == rfUndef:
    return restError(Http404, "output format not found (available: " & availableFormatsString() & ")")

  let txid = try:
    parseTxId(txidStr)
  except CatchableError:
    return restError(Http400, "Invalid hash: " & txidStr)

  # Check mempool first
  let mempoolTx = rest.mempool.getTransaction(txid)
  if mempoolTx.isSome:
    let tx = mempoolTx.get()
    case rf
    of rfBinary:
      return restBinary(serialize(tx))
    of rfHex:
      return restHex(serialize(tx))
    of rfJson:
      let weight = consensus_validation.calculateTransactionWeight(tx)
      return restJson(%*{
        "txid": reverseHex(toHex(array[32, byte](txid))),
        "hash": reverseHex(toHex(array[32, byte](tx.wtxid()))),
        "version": tx.version,
        "size": serialize(tx).len,
        "vsize": (weight + 3) div 4,
        "weight": weight,
        "locktime": tx.lockTime,
        "hex": toHex(serialize(tx))
      })
    else:
      discard

  # Check tx index for confirmed transactions
  let locOpt = rest.chainState.db.getTxIndex(txid)
  if locOpt.isNone:
    return restError(Http404, txidStr & " not found")

  let loc = locOpt.get()
  let blkOpt = rest.chainState.db.getBlock(loc.blockHash)
  if blkOpt.isNone:
    return restError(Http500, "Block not found for indexed transaction")

  let blk = blkOpt.get()
  if int(loc.txIndex) >= blk.txs.len:
    return restError(Http500, "Invalid transaction index")

  let tx = blk.txs[loc.txIndex]

  case rf
  of rfBinary:
    restBinary(serialize(tx))
  of rfHex:
    restHex(serialize(tx))
  of rfJson:
    let weight = consensus_validation.calculateTransactionWeight(tx)
    restJson(%*{
      "txid": reverseHex(toHex(array[32, byte](txid))),
      "hash": reverseHex(toHex(array[32, byte](tx.wtxid()))),
      "version": tx.version,
      "size": serialize(tx).len,
      "vsize": (weight + 3) div 4,
      "weight": weight,
      "locktime": tx.lockTime,
      "blockhash": reverseHex(toHex(array[32, byte](loc.blockHash))),
      "hex": toHex(serialize(tx))
    })
  else:
    restError(Http404, "output format not found")

# ============================================================================
# UTXO endpoint
# ============================================================================

proc handleRestGetUtxos*(rest: RestServer, uriPart: string): RestResponse =
  ## GET /rest/getutxos/<checkmempool>/<txid-vout>/...<format>
  ## Check UTXO status for specified outpoints
  var param = uriPart
  let rf = parseDataFormat(param, uriPart)

  if rf == rfUndef:
    return restError(Http404, "output format not found (available: " & availableFormatsString() & ")")

  # Parse path: /checkmempool/txid1-n/txid2-n/...
  if param.len == 0 or param == "/":
    return restError(Http400, "Error: empty request")

  var parts = param.strip(chars = {'/'}).split('/')
  if parts.len == 0:
    return restError(Http400, "Error: empty request")

  var checkMempool = false
  var startIdx = 0

  if parts[0] == "checkmempool":
    checkMempool = true
    startIdx = 1

  if startIdx >= parts.len:
    return restError(Http400, "Error: empty request")

  var outpoints: seq[OutPoint]
  for i in startIdx ..< parts.len:
    let outpointParts = parts[i].split('-')
    if outpointParts.len != 2:
      return restError(Http400, "Parse error")

    let txid = try:
      parseTxId(outpointParts[0])
    except CatchableError:
      return restError(Http400, "Parse error")

    let vout = try:
      uint32(parseInt(outpointParts[1]))
    except ValueError:
      return restError(Http400, "Parse error")

    outpoints.add(OutPoint(txid: txid, vout: vout))

  if outpoints.len > MaxGetUtxosOutpoints:
    return restError(Http400, "Error: max outpoints exceeded (max: " & $MaxGetUtxosOutpoints & ")")

  # Check each outpoint
  var bitmap: seq[byte]
  bitmap.setLen((outpoints.len + 7) div 8)
  var hits: seq[bool]
  var utxos: seq[tuple[height: int32, output: TxOut]]
  var bitmapStr = ""

  for i, outpoint in outpoints:
    var found = false

    # Check chainstate UTXO set
    let utxoOpt = rest.chainState.getUtxo(outpoint)
    if utxoOpt.isSome:
      # Check if mempool has a spend (if checkMempool enabled)
      if checkMempool and rest.mempool.isSpent(outpoint):
        found = false
      else:
        found = true
        utxos.add((utxoOpt.get().height, utxoOpt.get().output))
    elif checkMempool:
      # Check if output was created by mempool tx
      let mempoolTx = rest.mempool.getTransaction(outpoint.txid)
      if mempoolTx.isSome and int(outpoint.vout) < mempoolTx.get().outputs.len:
        found = true
        utxos.add((int32(-1), mempoolTx.get().outputs[outpoint.vout]))  # -1 for unconfirmed

    hits.add(found)
    bitmapStr.add(if found: "1" else: "0")
    if found:
      bitmap[i div 8] = bitmap[i div 8] or byte(1 shl (i mod 8))

  let chainHeight = rest.chainState.bestHeight
  let chainTipHash = rest.chainState.bestBlockHash

  case rf
  of rfBinary:
    # Serialize: height (4) + hash (32) + bitmap + utxos
    var data: seq[byte]
    # Height (little-endian)
    data.add(byte(chainHeight and 0xff))
    data.add(byte((chainHeight shr 8) and 0xff))
    data.add(byte((chainHeight shr 16) and 0xff))
    data.add(byte((chainHeight shr 24) and 0xff))
    # Chain tip hash
    data.add(@(array[32, byte](chainTipHash)))
    # Bitmap
    data.add(bitmap)
    # UTXOs (simplified: just height + value + scriptPubKey)
    for (height, output) in utxos:
      # Version dummy (4 bytes)
      data.add([byte(0), 0, 0, 0])
      # Height (4 bytes)
      data.add(byte(height and 0xff))
      data.add(byte((height shr 8) and 0xff))
      data.add(byte((height shr 16) and 0xff))
      data.add(byte((height shr 24) and 0xff))
      # TxOut (value + scriptPubKey)
      let value = int64(output.value)
      for j in 0 ..< 8:
        data.add(byte((value shr (j * 8)) and 0xff))
      # CompactSize for script length
      if output.scriptPubKey.len < 0xFD:
        data.add(byte(output.scriptPubKey.len))
      else:
        data.add(byte(0xFD))
        data.add(byte(output.scriptPubKey.len and 0xff))
        data.add(byte((output.scriptPubKey.len shr 8) and 0xff))
      data.add(output.scriptPubKey)
    restBinary(data)
  of rfHex:
    var data: seq[byte]
    data.add(byte(chainHeight and 0xff))
    data.add(byte((chainHeight shr 8) and 0xff))
    data.add(byte((chainHeight shr 16) and 0xff))
    data.add(byte((chainHeight shr 24) and 0xff))
    data.add(@(array[32, byte](chainTipHash)))
    data.add(bitmap)
    for (height, output) in utxos:
      data.add([byte(0), 0, 0, 0])
      data.add(byte(height and 0xff))
      data.add(byte((height shr 8) and 0xff))
      data.add(byte((height shr 16) and 0xff))
      data.add(byte((height shr 24) and 0xff))
      let value = int64(output.value)
      for j in 0 ..< 8:
        data.add(byte((value shr (j * 8)) and 0xff))
      if output.scriptPubKey.len < 0xFD:
        data.add(byte(output.scriptPubKey.len))
      else:
        data.add(byte(0xFD))
        data.add(byte(output.scriptPubKey.len and 0xff))
        data.add(byte((output.scriptPubKey.len shr 8) and 0xff))
      data.add(output.scriptPubKey)
    restHex(data)
  of rfJson:
    var utxoArray = newJArray()
    for (height, output) in utxos:
      utxoArray.add(%*{
        "height": height,
        "value": float64(int64(output.value)) / 100_000_000.0,
        "scriptPubKey": %*{
          "hex": toHex(output.scriptPubKey)
        }
      })
    restJson(%*{
      "chainHeight": chainHeight,
      "chaintipHash": reverseHex(toHex(array[32, byte](chainTipHash))),
      "bitmap": bitmapStr,
      "utxos": utxoArray
    })
  else:
    restError(Http404, "output format not found")

# ============================================================================
# Mempool endpoints
# ============================================================================

proc handleRestMempoolInfo*(rest: RestServer): RestResponse =
  ## GET /rest/mempool/info.json
  let minFee = rest.mempool.minFeeRate / 100000000.0  # sat/vbyte to BTC/kB
  restJson(%*{
    "loaded": true,
    "size": rest.mempool.count,
    "bytes": rest.mempool.size,
    "usage": rest.mempool.size,
    "maxmempool": rest.mempool.maxSize,
    "mempoolminfee": minFee,
    "minrelaytxfee": minFee
  })

proc handleRestMempoolContents*(rest: RestServer): RestResponse =
  ## GET /rest/mempool/contents.json
  var entries = newJObject()
  for txid, entry in rest.mempool.entries:
    let vsize = (entry.weight + 3) div 4
    entries[reverseHex(toHex(array[32, byte](txid)))] = %*{
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
  restJson(entries)

# ============================================================================
# Request routing
# ============================================================================

proc handleRestRequest*(rest: RestServer, path: string): RestResponse =
  ## Route a REST request to the appropriate handler
  ## path should be the URI path starting with /rest/

  # Strip leading /rest
  let cleanPath = if path.startsWith("/rest/"): path[6 .. ^1]
                  elif path.startsWith("/rest"): path[5 .. ^1]
                  else: path

  # Route to handlers
  if cleanPath.startsWith("block/notxdetails/"):
    return rest.handleRestBlockNoTxDetails(cleanPath[18 .. ^1])

  if cleanPath.startsWith("block/"):
    return rest.handleRestBlock(cleanPath[6 .. ^1])

  if cleanPath.startsWith("headers/"):
    return rest.handleRestHeaders(cleanPath[8 .. ^1])

  if cleanPath.startsWith("blockhashbyheight/"):
    return rest.handleRestBlockHashByHeight(cleanPath[18 .. ^1])

  if cleanPath.startsWith("tx/"):
    return rest.handleRestTx(cleanPath[3 .. ^1])

  if cleanPath.startsWith("getutxos/"):
    return rest.handleRestGetUtxos(cleanPath[9 .. ^1])

  if cleanPath == "mempool/info.json":
    return rest.handleRestMempoolInfo()

  if cleanPath == "mempool/contents.json":
    return rest.handleRestMempoolContents()

  restError(Http404, "Not found")

# ============================================================================
# HTTP Server
# ============================================================================

proc formatHttpResponse(resp: RestResponse): string =
  "HTTP/1.1 " & $resp.status & "\r\n" &
  "Content-Type: " & resp.contentType & "\r\n" &
  "Content-Length: " & $resp.body.len & "\r\n" &
  "Access-Control-Allow-Origin: *\r\n" &
  "\r\n" & resp.body

proc processRestClient(rest: RestServer, transp: StreamTransport) {.async.} =
  ## Handle a single REST client connection
  var inHeaders = true
  var path = ""

  while not transp.closed:
    try:
      let line = await transp.readLine()

      if inHeaders:
        if line.len == 0:
          # End of headers - process request
          inHeaders = false

          if path.len > 0:
            var resp: RestResponse
            {.gcsafe.}:
              try:
                resp = rest.handleRestRequest(path)
              except CatchableError as e:
                resp = restError(Http500, "Internal error: " & e.msg)

            let httpResponse = formatHttpResponse(resp)
            discard await transp.write(httpResponse)

          # Reset for keep-alive
          inHeaders = true
          path = ""

        elif line.startsWith("GET "):
          # Extract path from GET request
          let parts = line.split(' ')
          if parts.len >= 2:
            path = parts[1]

        # Skip other headers

    except CatchableError:
      break

  await transp.closeWait()

proc start*(rest: RestServer) {.async.} =
  ## Start the REST server
  let ta = initTAddress("127.0.0.1", Port(rest.port))
  let server = createStreamServer(ta, flags = {ReuseAddr})

  rest.running = true
  info "REST server started", port = rest.port

  while rest.running:
    try:
      let transp = await server.accept()
      asyncSpawn rest.processRestClient(transp)
    except CatchableError as e:
      if rest.running:
        error "REST server error", error = e.msg

  server.close()

proc stop*(rest: RestServer) =
  rest.running = false
