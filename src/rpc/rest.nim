## REST API server
## Read-only HTTP endpoints for blockchain queries
## Supports JSON, binary, and hex formats
## No authentication required (read-only)
##
## Reference: Bitcoin Core rest.cpp
##
## Transport: defaults to plaintext HTTP for backward compatibility.  When
## `--rpc-tls-cert` and `--rpc-tls-key` are both set, the listener wraps
## each accepted connection in a `chronos/streams/tlsstream` TLS server
## session (HTTPS).  The PEM-encoded cert and PKCS#8 PEM key are loaded
## once at startup; failures abort the listener immediately rather than
## silently fall back to plaintext.  W119 + FIX-64.

import std/[json, strutils, tables, options, times, os]
import chronos
import chronos/streams/[asyncstream, tlsstream]
import chronicles
import ../primitives/[types, serialize]
import ../consensus/params
import ../consensus/validation as consensus_validation
import ../storage/[chainstate, blockstore]
import ../storage/indexes/txindex
import ../storage/indexes/blockfilterindex
import ../storage/indexes/gcs
import ../mempool/mempool
import ../crypto/hashing
import ../wallet/wallet
import ../wallet/payjoin as payjoinMod

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
    filterIndex*: BlockFilterIndex  ## Optional: BIP-157 cfilter / cfheader lookup
    # ---- TLS termination (W119 + FIX-64) ----
    tlsEnabled*: bool             ## True when both cert+key were loaded.
                                  ## When false, the listener is plaintext
                                  ## HTTP (backward-compatible default).
    tlsCertPath*: string          ## On-disk PEM cert path (informational).
    tlsKeyPath*: string           ## On-disk PKCS#8 PEM key path (informational).
    tlsPrivateKey*: TLSPrivateKey ## Loaded once at startup; reused per accept.
    tlsCertificate*: TLSCertificate ## Loaded once at startup; reused per accept.
    # ---- PayJoin receiver (W119 + FIX-65) ----
    wallet*: Wallet               ## Optional: when set, enables POST
                                  ## /payjoin BIP-78 receiver endpoint.
                                  ## nil ⇒ POST /payjoin → 404 (the
                                  ## existing read-only REST contract).
    payjoinSessions*: PayJoinSessionTable
      ## Replay-protection + TTL table for the receiver path.
      ## Initialised when `wallet` is provided so the same RestServer
      ## instance can be carried across many POSTs.

const
  MaxGetUtxosOutpoints* = 15  ## Max outpoints per getutxos request
  MaxRestHeadersResults* = 2000  ## Max headers per request

proc newRestError(msg: string): ref RestError =
  newException(RestError, msg)

proc loadTlsMaterial(certPath, keyPath: string):
    tuple[cert: TLSCertificate, key: TLSPrivateKey] =
  ## Load and parse the PEM cert + PKCS#8 PEM key from disk.
  ##
  ## Returns the parsed pair on success; raises `RestError` with a
  ## descriptive message on any failure (missing file, bad encoding,
  ## unsupported key type).  Callers MUST treat any exception as fatal
  ## and refuse to start the listener — silently falling back to
  ## plaintext when TLS was requested would defeat BIP-78 §Protocol's
  ## HTTPS requirement.
  if certPath.len == 0:
    raise newRestError("TLS cert path is empty")
  if keyPath.len == 0:
    raise newRestError("TLS key path is empty")
  if not fileExists(certPath):
    raise newRestError("TLS cert file not found: " & certPath)
  if not fileExists(keyPath):
    raise newRestError("TLS key file not found: " & keyPath)

  let certPem =
    try: readFile(certPath)
    except IOError as e:
      raise newRestError("failed to read TLS cert " & certPath & ": " & e.msg)
  let keyPem =
    try: readFile(keyPath)
    except IOError as e:
      raise newRestError("failed to read TLS key " & keyPath & ": " & e.msg)

  let cert =
    try: TLSCertificate.init(certPem)
    except TLSStreamProtocolError as e:
      raise newRestError("invalid TLS cert " & certPath & ": " & e.msg)
  let key =
    try: TLSPrivateKey.init(keyPem)
    except TLSStreamProtocolError as e:
      raise newRestError("invalid TLS key " & keyPath & ": " & e.msg)

  (cert: cert, key: key)

proc newRestServer*(
  port: uint16,
  chainState: ChainState,
  mempool: Mempool,
  params: ConsensusParams,
  txIndex: TxIndex = nil,
  filterIndex: BlockFilterIndex = nil,
  tlsCertPath: string = "",
  tlsKeyPath: string = "",
  wallet: Wallet = nil
): RestServer =
  ## Construct a REST server.
  ##
  ## TLS is enabled iff BOTH `tlsCertPath` and `tlsKeyPath` are non-empty.
  ## Passing exactly one of the two is an operator mistake and raises
  ## `RestError` so the caller can fail fast at startup instead of
  ## silently downgrading to HTTP.  Pass both empty (the default) to keep
  ## the existing plaintext behaviour.  W119 + FIX-64.
  let tlsRequested = tlsCertPath.len > 0 or tlsKeyPath.len > 0
  let tlsBothSet = tlsCertPath.len > 0 and tlsKeyPath.len > 0
  if tlsRequested and not tlsBothSet:
    raise newRestError(
      "--rpc-tls-cert and --rpc-tls-key must both be set (or both empty); " &
      "got cert='" & tlsCertPath & "', key='" & tlsKeyPath & "'")

  var srv = RestServer(
    port: port,
    chainState: chainState,
    mempool: mempool,
    params: params,
    running: false,
    txIndex: txIndex,
    filterIndex: filterIndex,
    tlsEnabled: false,
    tlsCertPath: "",
    tlsKeyPath: "",
    tlsPrivateKey: nil,
    tlsCertificate: nil,
    wallet: wallet,
    payjoinSessions: (if wallet != nil: newPayJoinSessionTable() else: nil)
  )

  if tlsBothSet:
    let (cert, key) = loadTlsMaterial(tlsCertPath, tlsKeyPath)
    srv.tlsEnabled = true
    srv.tlsCertPath = tlsCertPath
    srv.tlsKeyPath = tlsKeyPath
    srv.tlsCertificate = cert
    srv.tlsPrivateKey = key

  srv

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
  let minFee = rest.mempool.minFeeRate / 100000.0  # sat/vbyte to BTC/kvB
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
# Block filter endpoints (BIP-157)
# ============================================================================

const
  MaxRestBlockfilterHeaders* = 2000
    ## Max cfheaders per request, mirrors MAX_REST_HEADERS_RESULTS in
    ## bitcoin-core/src/rest.cpp.

proc parseBlockFilterType*(name: string): Option[BlockFilterType] =
  ## Mirrors Bitcoin Core's `BlockFilterTypeByName`. Only "basic" is currently
  ## defined per BIP-158, but we keep the table-shaped API for forward
  ## compatibility with any new filter type the BIP series adds later.
  case name.toLowerAscii
  of "basic": some(bftBasic)
  else: none(BlockFilterType)

proc encodeBlockFilterRecord*(filter: BlockFilter): seq[byte] =
  ## Same wire shape as Bitcoin Core's `DataStream ssResp{}; ssResp << filter;`
  ## (see rest.cpp::rest_block_filter and blockfilter.h SerializationOps).
  ## A filter is serialized as `compactsize_len(filter) || filter_bytes`.
  let encoded = getEncodedFilter(filter)
  var w = BinaryWriter()
  w.writeCompactSize(uint64(encoded.len))
  result = w.data
  result.add(encoded)

proc handleRestBlockFilter*(rest: RestServer, uriPart: string): RestResponse =
  ## GET /rest/blockfilter/<filtertype>/<blockhash>.<format>
  ## Reference: bitcoin-core/src/rest.cpp::rest_block_filter (line 622).
  var param = uriPart
  let rf = parseDataFormat(param, uriPart)

  if rf == rfUndef:
    return restError(Http404, "output format not found (available: " &
                              availableFormatsString() & ")")

  let parts = param.split('/')
  if parts.len != 2:
    return restError(Http400,
      "Invalid URI format. Expected /rest/blockfilter/<filtertype>/<blockhash>")

  let typeName = parts[0]
  let hashStr = parts[1]

  let filterTypeOpt = parseBlockFilterType(typeName)
  if filterTypeOpt.isNone:
    return restError(Http400, "Unknown filtertype " & typeName)
  let filterType = filterTypeOpt.get()

  let blockHash = try:
    parseBlockHash(hashStr)
  except CatchableError:
    return restError(Http400, "Invalid hash: " & hashStr)

  if rest.filterIndex == nil or not rest.filterIndex.enabled:
    return restError(Http400,
      "Index is not enabled for filtertype " & typeName)

  if rest.filterIndex.filterType != filterType:
    return restError(Http400,
      "Index is not enabled for filtertype " & typeName)

  let idxOpt = rest.chainState.db.getBlockIndex(blockHash)
  if idxOpt.isNone:
    return restError(Http404, hashStr & " not found")
  let height = idxOpt.get().height

  # Confirm the requested block is on the active chain — Core only serves
  # filters for blocks that were connected (BLOCK_VALID_SCRIPTS). We mirror
  # that by checking that the height->hash mapping resolves to the same hash.
  let activeOpt = rest.chainState.db.getBlockHashByHeight(height)
  let blockWasConnected = activeOpt.isSome and activeOpt.get() == blockHash

  let filterOpt = rest.filterIndex.getFilter(height, blockHash)
  if filterOpt.isNone:
    var errmsg = "Filter not found."
    if not blockWasConnected:
      errmsg.add(" Block was not connected to active chain.")
    elif rest.filterIndex.bestHeight < height:
      errmsg.add(" Block filters are still in the process of being indexed.")
    else:
      errmsg.add(" This error is unexpected and indicates index corruption.")
    return restError(Http404, errmsg)

  let filter = filterOpt.get()

  case rf
  of rfBinary:
    restBinary(encodeBlockFilterRecord(filter))
  of rfHex:
    restHex(encodeBlockFilterRecord(filter))
  of rfJson:
    restJson(%*{"filter": toHex(getEncodedFilter(filter))})
  else:
    restError(Http404, "output format not found")

proc handleRestBlockFilterHeaders*(rest: RestServer, uriPart: string): RestResponse =
  ## GET /rest/blockfilterheaders/<filtertype>/<count>/<blockhash>.<format>
  ## (deprecated path, still served for parity)
  ## GET /rest/blockfilterheaders/<filtertype>/<blockhash>.<format>?count=<N>
  ## (new path with query parameter — Core 28+)
  ## Reference: bitcoin-core/src/rest.cpp::rest_filter_header (line 500).
  var param = uriPart
  let rf = parseDataFormat(param, uriPart)

  if rf == rfUndef:
    return restError(Http404, "output format not found (available: " &
                              availableFormatsString() & ")")

  # Strip query string (?count=N) before splitting; remember it for the
  # 2-segment new-style path.
  var queryCount = ""
  let qpos = param.find('?')
  if qpos >= 0:
    let qs = param[qpos + 1 .. ^1]
    param = param[0 ..< qpos]
    for kv in qs.split('&'):
      let eq = kv.find('=')
      if eq > 0 and kv[0 ..< eq] == "count":
        queryCount = kv[eq + 1 .. ^1]

  let parts = param.split('/')
  var typeName = ""
  var rawCount = ""
  var hashStr = ""

  if parts.len == 3:
    # Deprecated path: /<filtertype>/<count>/<blockhash>
    typeName = parts[0]
    rawCount = parts[1]
    hashStr = parts[2]
  elif parts.len == 2:
    # New path: /<filtertype>/<blockhash>?count=N
    typeName = parts[0]
    hashStr = parts[1]
    rawCount = if queryCount.len > 0: queryCount else: "5"
  else:
    return restError(Http400,
      "Invalid URI format. Expected /rest/blockfilterheaders/" &
      "<filtertype>/<blockhash>.<ext>?count=<count>")

  let count = try:
    parseInt(rawCount)
  except ValueError:
    return restError(Http400,
      "Header count is invalid or out of acceptable range (1-" &
      $MaxRestBlockfilterHeaders & "): " & rawCount)

  if count < 1 or count > MaxRestBlockfilterHeaders:
    return restError(Http400,
      "Header count is invalid or out of acceptable range (1-" &
      $MaxRestBlockfilterHeaders & "): " & rawCount)

  let filterTypeOpt = parseBlockFilterType(typeName)
  if filterTypeOpt.isNone:
    return restError(Http400, "Unknown filtertype " & typeName)
  let filterType = filterTypeOpt.get()

  let blockHash = try:
    parseBlockHash(hashStr)
  except CatchableError:
    return restError(Http400, "Invalid hash: " & hashStr)

  if rest.filterIndex == nil or not rest.filterIndex.enabled:
    return restError(Http400,
      "Index is not enabled for filtertype " & typeName)

  if rest.filterIndex.filterType != filterType:
    return restError(Http400,
      "Index is not enabled for filtertype " & typeName)

  # Walk the active chain forward from the requested hash, mirroring
  # Core's `while (pindex && active_chain.Contains(pindex))` loop.
  let idxOpt = rest.chainState.db.getBlockIndex(blockHash)
  if idxOpt.isNone:
    return restError(Http404, hashStr & " not found")
  let startHeight = idxOpt.get().height

  let activeStart = rest.chainState.db.getBlockHashByHeight(startHeight)
  if activeStart.isNone or activeStart.get() != blockHash:
    return restError(Http404, hashStr & " not found")

  var filterHeaders: seq[array[32, byte]]
  filterHeaders.setLen(0)
  var h = startHeight
  while filterHeaders.len < count and h <= rest.chainState.bestHeight:
    let entryOpt = rest.filterIndex.getFilterEntry(h)
    if entryOpt.isNone:
      var errmsg = "Filter not found."
      if rest.filterIndex.bestHeight < h:
        errmsg.add(" Block filters are still in the process of being indexed.")
      else:
        errmsg.add(" This error is unexpected and indicates index corruption.")
      return restError(Http404, errmsg)
    filterHeaders.add(entryOpt.get().filterHeader)
    inc h

  case rf
  of rfBinary:
    var data: seq[byte]
    for fh in filterHeaders:
      data.add(@fh)
    restBinary(data)
  of rfHex:
    var data: seq[byte]
    for fh in filterHeaders:
      data.add(@fh)
    restHex(data)
  of rfJson:
    var arr = newJArray()
    for fh in filterHeaders:
      arr.add(%reverseHex(toHex(fh)))
    restJson(arr)
  else:
    restError(Http404, "output format not found")

# ============================================================================
# Request routing
# ============================================================================

# ============================================================================
# PayJoin POST endpoint (W119 + FIX-65)
# ============================================================================

proc payjoinErrorBody(kind: PayJoinErrorKind, message: string): string =
  ## BIP-78 §"Receive request errors" body shape — JSON object with
  ## `errorCode` (the canonical string from the enum) + free-form
  ## `message`. We hand-build the object so the dependency on
  ## `std/json` stays minimal and the wire body is stable byte-for-byte.
  let j = %*{
    "errorCode": $kind,
    "message": message
  }
  $j

proc payjoinHttpStatusFor(kind: PayJoinErrorKind): HttpStatusCode =
  ## BIP-78 §"Receive request errors" suggests 4xx for sender-induced
  ## failures and 503 for receiver-induced. We use:
  ##   * 400  for malformed Original PSBT or version mismatch
  ##   * 503  for receiver-side `unavailable` / `not-enough-money`
  case kind
  of pjeOriginalPsbtRejected, pjeVersionUnsupported: Http400
  of pjeUnavailable, pjeNotEnoughMoney: Http503

proc handleRestPayJoin*(rest: RestServer, query: string,
                       contentType: string, body: string): RestResponse =
  ## POST /payjoin entry. Returns a `RestResponse` whose JSON body is
  ## either a BIP-78 proposal (base64 PSBT wrapped in `{"psbt":...}`)
  ## or a BIP-78 error envelope.
  ##
  ## Contract:
  ##   * If the RestServer has no wallet wired, return 404 (the
  ##     existing read-only contract is preserved by default).
  ##   * Content-Type MUST be text/plain; otherwise 400 with
  ##     `original-psbt-rejected`.
  ##   * Body is the base64 Original PSBT.
  ##   * On success the response body is `<base64 PSBT proposal>` as
  ##     plain text (Content-Type: text/plain) — BIP-78 §"Receiver"
  ##     specifies a raw base64 body, not JSON. We surface that exactly.
  if rest.wallet == nil:
    return restError(Http404, "PayJoin endpoint disabled (no wallet)")

  if not checkPayJoinContentType(contentType):
    return RestResponse(
      status: Http400,
      contentType: "application/json",
      body: payjoinErrorBody(pjeOriginalPsbtRejected,
        "Content-Type must be text/plain (got '" & contentType & "')") &
        "\r\n")

  var w = rest.wallet
  let height =
    if rest.chainState != nil: rest.chainState.bestHeight
    else: 0'i32

  try:
    let proposal = payjoinReceive(
      w, body.strip(), query, rest.payjoinSessions, height)
    return RestResponse(
      status: Http200,
      contentType: "text/plain",
      body: proposal)
  except PayJoinError as e:
    return RestResponse(
      status: payjoinHttpStatusFor(e.kind),
      contentType: "application/json",
      body: payjoinErrorBody(e.kind, e.msg) & "\r\n")
  except CatchableError as e:
    return RestResponse(
      status: Http500,
      contentType: "application/json",
      body: payjoinErrorBody(pjeUnavailable,
        "Internal receiver error: " & e.msg) & "\r\n")

proc handleRestPayJoinPost*(rest: RestServer, query: string,
                           contentType: string, body: string): RestResponse =
  ## Audit alias (W119 G1 surface) — `check not compiles(handleRestPayJoinPost)`
  ## was the pinned assertion; FIX-65 flips it to compiles.
  handleRestPayJoin(rest, query, contentType, body)

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

  # NOTE: order matters — `blockfilterheaders/` must be checked before
  # `blockfilter/`, otherwise the headers prefix matches the filter route.
  if cleanPath.startsWith("blockfilterheaders/"):
    return rest.handleRestBlockFilterHeaders(cleanPath[19 .. ^1])

  if cleanPath.startsWith("blockfilter/"):
    return rest.handleRestBlockFilter(cleanPath[12 .. ^1])

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

proc processStream(rest: RestServer,
                   reader: AsyncStreamReader,
                   writer: AsyncStreamWriter) {.async.} =
  ## Generic HTTP/1.1 mini-parser working over any chronos AsyncStream
  ## pair.  Used for both the plaintext path (reader/writer wrap the raw
  ## transport directly) and the HTTPS path (reader/writer are the TLS
  ## stream halves and have already completed the handshake before the
  ## first call).
  ##
  ## FIX-65 extended this from GET-only to GET+POST. POST is needed for
  ## the BIP-78 PayJoin receiver endpoint (`POST /payjoin?...`). The
  ## parser reads the request line, captures `Content-Length` and
  ## `Content-Type`, then on the blank line either dispatches (GET) or
  ## reads `Content-Length` bytes of body before dispatching (POST).
  var inHeaders = true
  var path = ""
  var meth = ""
  var contentLength: int = 0
  var contentType: string = ""

  while not reader.atEof():
    try:
      let line = await reader.readLine()

      if inHeaders:
        if line.len == 0:
          # End of headers - process request
          inHeaders = false

          var resp: RestResponse
          if meth == "GET" and path.len > 0:
            {.gcsafe.}:
              try:
                resp = rest.handleRestRequest(path)
              except CatchableError as e:
                resp = restError(Http500, "Internal error: " & e.msg)
            let httpResponse = formatHttpResponse(resp)
            await writer.write(httpResponse)
          elif meth == "POST" and path.len > 0:
            # Read body of exactly contentLength bytes. Cap at 4 MiB
            # (more than enough for any base64 PSBT — even a 200-input
            # Original PSBT is well under 200 KiB).
            const MaxPostBody = 4 * 1024 * 1024
            var body = ""
            if contentLength > MaxPostBody:
              resp = restError(Http400,
                "Content-Length exceeds receiver limit (" &
                $MaxPostBody & ")")
              let httpResponse = formatHttpResponse(resp)
              await writer.write(httpResponse)
            elif contentLength > 0:
              try:
                var buf = newSeq[byte](contentLength)
                await reader.readExactly(addr buf[0], contentLength)
                body = newString(contentLength)
                if contentLength > 0:
                  copyMem(addr body[0], addr buf[0], contentLength)
              except CatchableError as e:
                resp = restError(Http400,
                  "Failed reading POST body: " & e.msg)
                let httpResponse = formatHttpResponse(resp)
                await writer.write(httpResponse)
                break
            # Dispatch POST routes. Currently only /payjoin is wired.
            let (postPath, postQuery) = block:
              let q = path.find('?')
              if q < 0: (path, "")
              else: (path[0 ..< q], path[q + 1 .. ^1])

            {.gcsafe.}:
              try:
                if postPath == "/payjoin" or postPath == "/rest/payjoin":
                  resp = rest.handleRestPayJoin(postQuery, contentType, body)
                else:
                  resp = restError(Http404,
                    "POST " & postPath & " not found")
              except CatchableError as e:
                resp = restError(Http500,
                  "Internal error: " & e.msg)
            let httpResponse = formatHttpResponse(resp)
            await writer.write(httpResponse)

          # Reset for keep-alive
          inHeaders = true
          path = ""
          meth = ""
          contentLength = 0
          contentType = ""

        elif line.startsWith("GET "):
          let parts = line.split(' ')
          if parts.len >= 2:
            meth = "GET"
            path = parts[1]

        elif line.startsWith("POST "):
          let parts = line.split(' ')
          if parts.len >= 2:
            meth = "POST"
            path = parts[1]

        else:
          # Header parsing — only the two we need.
          let colon = line.find(':')
          if colon > 0:
            let hk = line[0 ..< colon].strip().toLowerAscii()
            let hv = line[colon + 1 .. ^1].strip()
            case hk
            of "content-length":
              try:
                contentLength = parseInt(hv)
              except ValueError:
                contentLength = 0
            of "content-type":
              contentType = hv
            else:
              discard
          # Other headers are skipped (no auth, no Host check on read-only).

    except CatchableError:
      break

proc processRestClient(rest: RestServer, transp: StreamTransport) {.async.} =
  ## Handle a single REST client connection.
  ##
  ## Plaintext path: wrap the transport in a chronos AsyncStream pair so
  ##   the protocol loop is shared with the TLS path.
  ## TLS path: wrap the transport, layer a `newTLSServerAsyncStream` on
  ##   top, run the TLS handshake, then hand the encrypted halves to the
  ##   shared loop.  The protocol on the wire is identical (HTTP/1.1);
  ##   the bytes on the socket are TLS records.
  let mainReader = newAsyncStreamReader(transp)
  let mainWriter = newAsyncStreamWriter(transp)

  if rest.tlsEnabled:
    var tlsStream: TLSAsyncStream
    try:
      tlsStream = newTLSServerAsyncStream(
        mainReader, mainWriter,
        rest.tlsPrivateKey,
        rest.tlsCertificate,
        minVersion = TLSVersion.TLS12)
    except TLSStreamError as e:
      error "REST/TLS stream init failed", error = e.msg
      await mainReader.closeWait()
      await mainWriter.closeWait()
      await transp.closeWait()
      return

    try:
      await handshake(tlsStream)
    except CatchableError as e:
      # Handshake failure is expected for probes / mismatched clients;
      # log at debug level and drop the connection cleanly.
      debug "REST/TLS handshake failed", error = e.msg
      try: await AsyncStreamReader(tlsStream.reader).closeWait()
      except CatchableError: discard
      try: await AsyncStreamWriter(tlsStream.writer).closeWait()
      except CatchableError: discard
      await mainReader.closeWait()
      await mainWriter.closeWait()
      await transp.closeWait()
      return

    try:
      await rest.processStream(
        AsyncStreamReader(tlsStream.reader),
        AsyncStreamWriter(tlsStream.writer))
    finally:
      try: await AsyncStreamReader(tlsStream.reader).closeWait()
      except CatchableError: discard
      try: await AsyncStreamWriter(tlsStream.writer).closeWait()
      except CatchableError: discard
      await mainReader.closeWait()
      await mainWriter.closeWait()
      await transp.closeWait()
  else:
    try:
      await rest.processStream(mainReader, mainWriter)
    finally:
      await mainReader.closeWait()
      await mainWriter.closeWait()
      await transp.closeWait()

proc start*(rest: RestServer) {.async.} =
  ## Start the REST server.
  ##
  ## The socket-level listener is identical for HTTP and HTTPS — the
  ## per-connection accept handler chooses whether to layer TLS based on
  ## `rest.tlsEnabled`.  This matches Bitcoin Core's libevent+OpenSSL
  ## pattern in `src/httpserver.cpp` (single listener, per-bufferevent
  ## SSL wrap).
  let ta = initTAddress("127.0.0.1", Port(rest.port))
  let server = createStreamServer(ta, flags = {ReuseAddr})

  rest.running = true
  if rest.tlsEnabled:
    info "REST server started (HTTPS)",
      port = rest.port, cert = rest.tlsCertPath
  else:
    info "REST server started (HTTP, no TLS)", port = rest.port

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
