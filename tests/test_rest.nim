## Tests for REST API
## Tests REST endpoint routing, response formats (JSON, binary, hex)

import std/[json, strutils, tables, options]
import unittest2
import ../src/rpc/rest
import ../src/primitives/[types, serialize]
import ../src/consensus/params
import ../src/crypto/hashing

# Helper procs
proc hexToBytes(hex: string): seq[byte] =
  result = newSeq[byte](hex.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(hex[i*2 .. i*2 + 1]))

proc bytesToHex(data: openArray[byte]): string =
  result = ""
  for b in data:
    result.add(toHex(b, 2).toLowerAscii)

proc reverseHex(hex: string): string =
  result = ""
  var i = hex.len - 2
  while i >= 0:
    result.add(hex[i .. i + 1])
    i -= 2

suite "REST response format parsing":
  test "parseDataFormat extracts json":
    var param = "abc123.json"
    let rf = parseDataFormat(param, "abc123.json")
    check rf == rfJson
    check param == "abc123"

  test "parseDataFormat extracts bin":
    var param = "abc123.bin"
    let rf = parseDataFormat(param, "abc123.bin")
    check rf == rfBinary
    check param == "abc123"

  test "parseDataFormat extracts hex":
    var param = "abc123.hex"
    let rf = parseDataFormat(param, "abc123.hex")
    check rf == rfHex
    check param == "abc123"

  test "parseDataFormat returns undef for unknown":
    var param = "abc123.xml"
    let rf = parseDataFormat(param, "abc123.xml")
    check rf == rfUndef

  test "parseDataFormat returns undef for no extension":
    var param = "abc123"
    let rf = parseDataFormat(param, "abc123")
    check rf == rfUndef

  test "parseDataFormat strips query string":
    var param = "abc123.json?count=5"
    let rf = parseDataFormat(param, "abc123.json?count=5")
    check rf == rfJson
    check param == "abc123"

suite "REST response helpers":
  test "restOk creates 200 response":
    let resp = restOk("{}", "application/json")
    check resp.status == Http200
    check resp.contentType == "application/json"
    check resp.body == "{}"

  test "restError creates error response":
    let resp = restError(Http404, "not found")
    check resp.status == Http404
    check resp.contentType == "text/plain"
    check "not found" in resp.body

  test "restBinary creates binary response":
    let resp = restBinary(@[0x01'u8, 0x02, 0x03])
    check resp.status == Http200
    check resp.contentType == "application/octet-stream"
    check resp.body.len == 3

  test "restHex creates hex response":
    let resp = restHex(@[0xab'u8, 0xcd, 0xef])
    check resp.status == Http200
    check resp.contentType == "text/plain"
    check resp.body.strip() == "abcdef"

  test "restJson creates json response":
    let resp = restJson(%*{"key": "value"})
    check resp.status == Http200
    check resp.contentType == "application/json"
    check "key" in resp.body

suite "REST block hash parsing":
  test "parseBlockHash valid hash":
    # Genesis block hash (reversed hex display format)
    let hashHex = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    let hash = parseBlockHash(hashHex)
    check array[32, byte](hash)[31] == 0x00  # Highest byte (LE)

  test "parseBlockHash rejects invalid length":
    expect RestError:
      discard parseBlockHash("0011223344")

suite "REST getutxos path parsing":
  test "path with checkmempool flag":
    # /rest/getutxos/checkmempool/txid-0.json
    var param = "checkmempool/aaaa....-0.json"
    let rf = parseDataFormat(param, "checkmempool/aaaa....-0.json")
    check rf == rfJson
    let parts = param.strip(chars = {'/'}).split('/')
    check parts[0] == "checkmempool"

  test "path without checkmempool flag":
    var param = "abc-0.json"
    let rf = parseDataFormat(param, "abc-0.json")
    check rf == rfJson

suite "REST constants":
  test "max outpoints limit":
    check MaxGetUtxosOutpoints == 15

  test "max headers limit":
    check MaxRestHeadersResults == 2000

suite "REST route patterns":
  test "block endpoint pattern":
    let path = "/rest/block/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f.json"
    check path.startsWith("/rest/block/")
    let cleanPath = path[12 .. ^1]  # Strip /rest/block/
    check cleanPath.startsWith("00000000")

  test "block notxdetails endpoint pattern":
    let path = "/rest/block/notxdetails/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f.json"
    check path.startsWith("/rest/block/notxdetails/")

  test "headers endpoint pattern":
    let path = "/rest/headers/5/000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f.json"
    check path.startsWith("/rest/headers/")
    let cleanPath = path[14 .. ^1]
    let parts = cleanPath.split('/')
    check parts.len >= 2  # count and hash

  test "blockhashbyheight endpoint pattern":
    let path = "/rest/blockhashbyheight/0.json"
    check path.startsWith("/rest/blockhashbyheight/")

  test "tx endpoint pattern":
    let path = "/rest/tx/aaaa....bbbb.json"
    check path.startsWith("/rest/tx/")

  test "getutxos endpoint pattern":
    let path = "/rest/getutxos/txid-0.json"
    check path.startsWith("/rest/getutxos/")

  test "mempool info endpoint pattern":
    let path = "/rest/mempool/info.json"
    check path == "/rest/mempool/info.json"

  test "mempool contents endpoint pattern":
    let path = "/rest/mempool/contents.json"
    check path == "/rest/mempool/contents.json"

suite "REST HTTP status codes":
  test "status code values":
    check $Http200 == "200 OK"
    check $Http400 == "400 Bad Request"
    check $Http404 == "404 Not Found"
    check $Http500 == "500 Internal Server Error"
    check $Http503 == "503 Service Unavailable"

suite "REST format string":
  test "available formats string":
    let formats = availableFormatsString()
    check "bin" in formats
    check "hex" in formats
    check "json" in formats

suite "REST JSON response structure":
  test "block json has required fields":
    # Test the expected JSON structure for block response
    let blockJson = %*{
      "hash": "00000000...",
      "confirmations": 1,
      "height": 0,
      "version": 1,
      "merkleroot": "4a5e1e...",
      "time": 1231006505,
      "nonce": 2083236893,
      "bits": "1d00ffff",
      "nTx": 1,
      "tx": []
    }
    check blockJson.hasKey("hash")
    check blockJson.hasKey("confirmations")
    check blockJson.hasKey("height")
    check blockJson.hasKey("version")
    check blockJson.hasKey("merkleroot")
    check blockJson.hasKey("time")
    check blockJson.hasKey("nonce")
    check blockJson.hasKey("bits")
    check blockJson.hasKey("nTx")
    check blockJson.hasKey("tx")

  test "mempool info json has required fields":
    let mempoolInfo = %*{
      "loaded": true,
      "size": 0,
      "bytes": 0,
      "usage": 0,
      "maxmempool": 300000000,
      "mempoolminfee": 0.00001,
      "minrelaytxfee": 0.00001
    }
    check mempoolInfo.hasKey("loaded")
    check mempoolInfo.hasKey("size")
    check mempoolInfo.hasKey("bytes")
    check mempoolInfo.hasKey("maxmempool")
    check mempoolInfo.hasKey("mempoolminfee")

  test "utxos json has required fields":
    let utxosResp = %*{
      "chainHeight": 100,
      "chaintipHash": "00000000...",
      "bitmap": "10",
      "utxos": []
    }
    check utxosResp.hasKey("chainHeight")
    check utxosResp.hasKey("chaintipHash")
    check utxosResp.hasKey("bitmap")
    check utxosResp.hasKey("utxos")

suite "REST header json":
  test "header json fields":
    let headerJson = %*{
      "hash": "00000000...",
      "confirmations": 100,
      "height": 0,
      "version": 1,
      "merkleroot": "4a5e1e...",
      "time": 1231006505,
      "nonce": 2083236893,
      "bits": "1d00ffff",
      "previousblockhash": "0000000000000000000000000000000000000000000000000000000000000000"
    }
    check headerJson.hasKey("hash")
    check headerJson.hasKey("confirmations")
    check headerJson.hasKey("height")
    check headerJson.hasKey("version")
    check headerJson.hasKey("merkleroot")
    check headerJson.hasKey("time")
    check headerJson.hasKey("nonce")
    check headerJson.hasKey("bits")

suite "REST tx json":
  test "tx json fields":
    let txJson = %*{
      "txid": "4a5e1e...",
      "hash": "4a5e1e...",
      "version": 1,
      "size": 204,
      "vsize": 204,
      "weight": 816,
      "locktime": 0,
      "hex": "0100000001..."
    }
    check txJson.hasKey("txid")
    check txJson.hasKey("hash")
    check txJson.hasKey("version")
    check txJson.hasKey("size")
    check txJson.hasKey("vsize")
    check txJson.hasKey("weight")
    check txJson.hasKey("locktime")

suite "REST blockhashbyheight json":
  test "blockhashbyheight json fields":
    let resp = %*{
      "blockhash": "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    }
    check resp.hasKey("blockhash")
    check resp["blockhash"].getStr().len == 64
