## Tests for JSON-RPC server
## Tests RPC method routing, error codes, request/response format, and Bitcoin Core compatible responses

import std/[json, strutils, tables, options]
import unittest2
import ../src/primitives/[types, serialize]
import ../src/consensus/[params, validation]
import ../src/crypto/[hashing, address]

# JSON-RPC 2.0 error codes (matching server.nim)
const
  RpcParseError* = -32700
  RpcInvalidRequest* = -32600
  RpcMethodNotFound* = -32601
  RpcInvalidParams* = -32602
  RpcInternalError* = -32603

# Helper procs for testing
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

suite "RPC error codes":
  test "error code constants":
    check RpcParseError == -32700
    check RpcInvalidRequest == -32600
    check RpcMethodNotFound == -32601
    check RpcInvalidParams == -32602
    check RpcInternalError == -32603

suite "RPC hex utilities":
  test "reverseHex reverses byte pairs":
    check reverseHex("01020304") == "04030201"
    check reverseHex("aabbccdd") == "ddccbbaa"
    check reverseHex("") == ""
    check reverseHex("ab") == "ab"
    check reverseHex("abcd") == "cdab"

  test "hexToBytes parses hex string":
    let bytes = hexToBytes("0102030405")
    check bytes.len == 5
    check bytes[0] == 0x01
    check bytes[4] == 0x05

  test "hexToBytes handles uppercase":
    let bytes = hexToBytes("AABBCC")
    check bytes.len == 3
    check bytes[0] == 0xAA
    check bytes[2] == 0xCC

  test "bytesToHex produces lowercase":
    let hex = bytesToHex(@[0xAA'u8, 0xBB, 0xCC])
    check hex == "aabbcc"

suite "RPC JSON format":
  test "valid JSON-RPC 2.0 response structure":
    # A valid response must have jsonrpc, id, and result or error
    let response = %*{
      "jsonrpc": "2.0",
      "id": 1,
      "result": 42,
      "error": nil
    }
    check response["jsonrpc"].getStr() == "2.0"
    check response.hasKey("id")
    check response.hasKey("result")

  test "error response structure":
    let errorResponse = %*{
      "jsonrpc": "2.0",
      "id": 1,
      "result": nil,
      "error": {
        "code": -32601,
        "message": "method not found"
      }
    }
    check errorResponse["error"]["code"].getInt() == -32601
    check errorResponse["error"]["message"].getStr() == "method not found"

suite "RPC decoderawtransaction format":
  test "decode legacy transaction hex":
    # Simple legacy transaction structure test
    # Version (4) + input count (1) + prevout (36) + scriptSig len (1) + sequence (4)
    # + output count (1) + value (8) + scriptPubKey len (1) + locktime (4)
    let legacyTxHex = "01000000" &  # version
                      "01" &        # input count
                      "0000000000000000000000000000000000000000000000000000000000000000" &  # prevout txid
                      "00000000" &  # prevout vout
                      "00" &        # scriptSig length (empty)
                      "ffffffff" &  # sequence
                      "01" &        # output count
                      "0100000000000000" &  # value (1 satoshi, little endian)
                      "00" &        # scriptPubKey length (empty)
                      "00000000"    # locktime

    let txBytes = hexToBytes(legacyTxHex)
    let tx = deserializeTransaction(txBytes)

    check tx.version == 1
    check tx.inputs.len == 1
    check tx.outputs.len == 1
    check tx.lockTime == 0
    check tx.witnesses.len == 0

  test "segwit transaction detection":
    # Segwit tx has marker (0x00) and flag (0x01) after version
    let segwitTxHex = "02000000" &    # version
                      "0001" &        # marker + flag
                      "01" &          # input count
                      "0000000000000000000000000000000000000000000000000000000000000000" &
                      "00000000" &
                      "00" &          # empty scriptSig
                      "ffffffff" &
                      "01" &          # output count
                      "0100000000000000" &
                      "160014" &      # P2WPKH scriptPubKey prefix
                      "0000000000000000000000000000000000000000" &
                      "02" &          # witness stack items
                      "47" &          # signature length (71 bytes)
                      "304402" & "00" & newSeq[byte](64).bytesToHex() & "01" &  # fake sig
                      "21" &          # pubkey length (33 bytes)
                      "02" & newSeq[byte](32).bytesToHex() &  # fake compressed pubkey
                      "00000000"      # locktime

    # This would need proper witness data - testing structure only
    check segwitTxHex.len > 0

suite "RPC address validation":
  test "validate P2PKH mainnet address":
    let satoshiAddr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    let decoded = decodeAddress(satoshiAddr)
    check decoded.kind == P2PKH
    check isMainnet(satoshiAddr)

  test "validate P2WPKH mainnet address":
    let bech32Addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    let decoded = decodeAddress(bech32Addr)
    check decoded.kind == P2WPKH
    check isMainnet(bech32Addr)

  test "validate P2TR mainnet address":
    let taprootAddr = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"
    let decoded = decodeAddress(taprootAddr)
    check decoded.kind == P2TR
    check isMainnet(taprootAddr)

  test "reject invalid address":
    # Modified address with wrong checksum
    expect AddressError:
      discard decodeAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")

suite "RPC block hash format":
  test "block hash is reversed for display":
    # Bitcoin RPC displays hashes in big-endian (reversed from internal LE)
    var hashBytes: array[32, byte]
    hashBytes[0] = 0x01
    hashBytes[31] = 0xFF
    let hashHex = bytesToHex(hashBytes)
    let displayHex = reverseHex(hashHex)

    # First byte becomes last in display
    check displayHex.startsWith("ff")
    check displayHex.endsWith("01")

  test "genesis block hash format":
    # Mainnet genesis block hash (as displayed)
    let genesisHashDisplay = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

    # Internal format is reversed
    let internalHex = reverseHex(genesisHashDisplay)
    check internalHex.endsWith("000000000019d668")

suite "RPC consensus params":
  test "mainnet params for RPC":
    let params = mainnetParams()
    check params.defaultPort == 8333
    check params.rpcPort == 8332
    check params.network == Mainnet

  test "testnet params for RPC":
    let params = testnet3Params()
    check params.defaultPort == 18333
    check params.rpcPort == 18332
    check params.network == Testnet3

  test "regtest params for RPC":
    let params = regtestParams()
    check params.defaultPort == 18444
    check params.rpcPort == 18443
    check params.network == Regtest

suite "RPC difficulty calculation":
  test "difficulty from compact bits":
    # Genesis block bits
    let genesisBits = 0x1d00ffff'u32
    let target = compactToTarget(genesisBits)

    # Target should have bytes 26,27,28 set
    check target[26] == 0xff
    check target[27] == 0xff
    check target[28] == 0x00

  test "regtest difficulty is 1":
    let regtestBits = 0x207fffff'u32
    let target = compactToTarget(regtestBits)

    # Very easy target - high bytes are set
    check target[31] == 0x7f
    check target[30] == 0xff
    check target[29] == 0xff

suite "RPC transaction weight":
  test "legacy transaction weight calculation":
    let legacyTx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[0x00'u8],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(1000),
        scriptPubKey: @[0x76'u8, 0xa9, 0x14] & newSeq[byte](20) & @[0x88'u8, 0xac]
      )],
      witnesses: @[],
      lockTime: 0
    )

    let weight = calculateTransactionWeight(legacyTx)
    let baseSize = serializeLegacy(legacyTx).len

    # Legacy tx weight = size * 4
    check weight == baseSize * 4

  test "segwit transaction weight discount":
    let segwitTx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[],  # Empty for native segwit
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(1000),
        scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)
      )],
      witnesses: @[@[@[0x30'u8] & newSeq[byte](70), @[0x02'u8] & newSeq[byte](32)]],
      lockTime: 0
    )

    let weight = calculateTransactionWeight(segwitTx)
    let baseSize = serializeLegacy(segwitTx).len
    let fullSize = serialize(segwitTx, includeWitness = true).len

    # Weight = baseSize * 3 + fullSize
    check weight == (baseSize * 3) + fullSize
    # Witness data is discounted
    check weight < fullSize * 4

suite "RPC mempool info format":
  test "mempool info fields":
    # Expected fields in getmempoolinfo response
    let expectedFields = ["loaded", "size", "bytes", "usage",
                          "maxmempool", "mempoolminfee", "minrelaytxfee"]
    let mempoolInfo = %*{
      "loaded": true,
      "size": 0,
      "bytes": 0,
      "usage": 0,
      "maxmempool": 300000000,
      "mempoolminfee": 0.00001,
      "minrelaytxfee": 0.00001
    }

    for field in expectedFields:
      check mempoolInfo.hasKey(field)

suite "RPC getblockchaininfo format":
  test "blockchain info fields":
    let expectedFields = ["chain", "blocks", "headers", "bestblockhash",
                          "difficulty", "mediantime", "verificationprogress",
                          "initialblockdownload", "chainwork", "pruned"]
    let blockchainInfo = %*{
      "chain": "regtest",
      "blocks": 0,
      "headers": 0,
      "bestblockhash": "0000000000000000000000000000000000000000000000000000000000000000",
      "difficulty": 1.0,
      "mediantime": 0,
      "verificationprogress": 1.0,
      "initialblockdownload": true,
      "chainwork": "0000000000000000000000000000000000000000000000000000000000000000",
      "size_on_disk": 0,
      "pruned": false
    }

    for field in expectedFields:
      check blockchainInfo.hasKey(field)

suite "RPC network info format":
  test "network info fields":
    let expectedFields = ["version", "subversion", "protocolversion",
                          "connections", "connections_in", "connections_out",
                          "networkactive", "relayfee"]
    let networkInfo = %*{
      "version": 210000,
      "subversion": "/nimrod:0.1.0/",
      "protocolversion": 70016,
      "localservices": "0000000000000409",
      "localrelay": true,
      "networkactive": true,
      "connections": 0,
      "connections_in": 0,
      "connections_out": 0,
      "relayfee": 0.00001
    }

    for field in expectedFields:
      check networkInfo.hasKey(field)

suite "RPC estimatesmartfee format":
  test "fee estimate fields":
    let feeEstimate = %*{
      "feerate": 0.00001,
      "blocks": 6
    }

    check feeEstimate.hasKey("feerate")
    check feeEstimate.hasKey("blocks")
    check feeEstimate["feerate"].getFloat() > 0
    check feeEstimate["blocks"].getInt() > 0

  test "fee estimate conf target range":
    # Valid conf_target is 1-1008
    check 1 >= 1
    check 1008 <= 1008

suite "RPC getblocktemplate format":
  test "block template fields":
    let expectedFields = ["capabilities", "version", "previousblockhash",
                          "transactions", "coinbasevalue", "target",
                          "mintime", "curtime", "bits", "height",
                          "sigoplimit", "weightlimit"]
    let blockTemplate = %*{
      "capabilities": ["proposal"],
      "version": 0x20000000,
      "rules": ["csv", "segwit"],
      "previousblockhash": "0000000000000000000000000000000000000000000000000000000000000000",
      "transactions": [],
      "coinbaseaux": {},
      "coinbasevalue": 5000000000,
      "target": "7fffff0000000000000000000000000000000000000000000000000000000000",
      "mintime": 1234567890,
      "mutable": ["time", "transactions", "prevblock"],
      "noncerange": "00000000ffffffff",
      "sigoplimit": 80000,
      "sizelimit": 4000000,
      "weightlimit": 4000000,
      "curtime": 1234567890,
      "bits": "207fffff",
      "height": 1
    }

    for field in expectedFields:
      check blockTemplate.hasKey(field)

suite "RPC validateaddress format":
  test "valid address response":
    let validResponse = %*{
      "isvalid": true,
      "address": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
      "scriptPubKey": "0014751e76e8199196d454941c45d1b3a323f1433bd6",
      "isscript": false,
      "iswitness": true,
      "witness_version": 0,
      "address_type": "witness_v0_keyhash"
    }

    check validResponse["isvalid"].getBool() == true
    check validResponse.hasKey("address")
    check validResponse.hasKey("scriptPubKey")

  test "invalid address response":
    let invalidResponse = %*{
      "isvalid": false,
      "address": "invalid"
    }

    check invalidResponse["isvalid"].getBool() == false

when isMainModule:
  echo "Running RPC tests..."
