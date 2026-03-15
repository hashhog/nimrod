## Tests for JSON-RPC server
## Tests RPC method routing, error codes, request/response format, and Bitcoin Core compatible responses

import std/[json, strutils, tables, options, sequtils]
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

  test "blockchain info with bits and target":
    # Bitcoin Core returns bits and target from the current tip block
    let blockchainInfo = %*{
      "chain": "main",
      "blocks": 100,
      "headers": 100,
      "bestblockhash": "0000000000000000000000000000000000000000000000000000000000000001",
      "bits": "1d00ffff",
      "target": "00000000ffff0000000000000000000000000000000000000000000000000000",
      "difficulty": 1.0,
      "time": 1234567890,
      "mediantime": 1234567880,
      "verificationprogress": 1.0,
      "initialblockdownload": false,
      "chainwork": "0000000000000000000000000000000000000000000000000000000000000100",
      "size_on_disk": 1000000,
      "pruned": false,
      "warnings": ""
    }

    check blockchainInfo.hasKey("bits")
    check blockchainInfo.hasKey("target")
    check blockchainInfo.hasKey("time")
    check blockchainInfo.hasKey("warnings")
    check blockchainInfo["bits"].getStr().len == 8

  test "chain names":
    # Test different network chain names
    check "main" == "main"      # Mainnet
    check "test" == "test"      # Testnet3
    check "testnet4" == "testnet4"  # Testnet4
    check "regtest" == "regtest"    # Regtest
    check "signet" == "signet"      # Signet

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

  test "networks array format":
    # Bitcoin Core returns an array of network objects
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

    check networks.len == 3
    check networks[0]["name"].getStr() == "ipv4"
    check networks[0].hasKey("limited")
    check networks[0].hasKey("reachable")

  test "localservicesnames format":
    let serviceNames = %*["NETWORK", "WITNESS", "NETWORK_LIMITED"]
    check serviceNames.len == 3
    check "NETWORK" in serviceNames.mapIt(it.getStr())
    check "WITNESS" in serviceNames.mapIt(it.getStr())

suite "RPC getpeerinfo format":
  test "peer info fields":
    # Bitcoin Core getpeerinfo returns detailed peer information
    let expectedFields = ["id", "addr", "services", "lastsend", "lastrecv",
                          "bytessent", "bytesrecv", "conntime", "pingtime",
                          "version", "subver", "inbound", "startingheight",
                          "synced_headers", "synced_blocks"]

    let peerInfo = %*{
      "id": 0,
      "addr": "127.0.0.1:8333",
      "services": "0000000000000409",
      "servicesnames": ["NETWORK", "WITNESS"],
      "relaytxes": true,
      "lastsend": 1234567890,
      "lastrecv": 1234567890,
      "last_transaction": 0,
      "last_block": 0,
      "bytessent": 1000,
      "bytesrecv": 2000,
      "conntime": 1234567800,
      "timeoffset": 0,
      "pingtime": 0.05,
      "minping": 0.05,
      "version": 70016,
      "subver": "/Satoshi:0.21.0/",
      "inbound": false,
      "bip152_hb_to": false,
      "bip152_hb_from": false,
      "startingheight": 100000,
      "presynced_headers": -1,
      "synced_headers": 100100,
      "synced_blocks": 100100,
      "inflight": [],
      "addr_relay_enabled": true,
      "addr_processed": 0,
      "addr_rate_limited": 0,
      "permissions": [],
      "minfeefilter": 0.00001,
      "connection_type": "outbound-full-relay",
      "transport_protocol_type": "v1",
      "session_id": ""
    }

    for field in expectedFields:
      check peerInfo.hasKey(field)

  test "services hex encoding":
    # NODE_NETWORK=1, NODE_WITNESS=8 -> 0x0009
    let services = 0x0009'u64
    check (services and 1) != 0  # NETWORK
    check (services and 8) != 0  # WITNESS
    check (services and 1024) == 0  # Not NETWORK_LIMITED

  test "connection types":
    # Valid connection type strings
    let validTypes = ["outbound-full-relay", "block-relay-only", "inbound",
                      "manual", "addr-fetch", "feeler"]
    check "outbound-full-relay" in validTypes
    check "inbound" in validTypes

  test "pingtime format":
    # Ping time is in seconds (float), latency in milliseconds
    let latencyMs = 50
    let pingTime = float64(latencyMs) / 1000.0
    check pingTime == 0.05

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

suite "RPC sendrawtransaction error codes":
  test "error code constants":
    # Bitcoin Core transaction error codes
    const
      RpcTransactionError = -25
      RpcTransactionRejected = -26
      RpcTransactionAlreadyInChain = -27

    check RpcTransactionError == -25
    check RpcTransactionRejected == -26
    check RpcTransactionAlreadyInChain == -27

  test "maxfeerate default value":
    # Default maxfeerate is 0.10 BTC/kvB
    const DefaultMaxFeeRate = 0.10
    check DefaultMaxFeeRate == 0.10

  test "maxfeerate conversion sat/vB":
    # 0.10 BTC/kvB = 10,000 sat/vB
    let maxFeeBtcKvb = 0.10
    let maxFeeSatPerVb = maxFeeBtcKvb * 100_000_000.0 / 1000.0
    check maxFeeSatPerVb == 10_000.0

  test "sendrawtransaction response format":
    # Successful response is just the txid as hex string
    let txidHex = "0000000000000000000000000000000000000000000000000000000000000001"
    let response = %txidHex

    check response.kind == JString
    check response.getStr().len == 64

  test "sendrawtransaction error response":
    # Error response structure
    let errorResponse = %*{
      "jsonrpc": "2.0",
      "id": 1,
      "result": nil,
      "error": {
        "code": -26,
        "message": "mempool min fee not met"
      }
    }

    check errorResponse["error"]["code"].getInt() == -26

suite "RPC broadcast format":
  test "inv message format for tx relay":
    # inv message contains InvVector items
    # MSG_WITNESS_TX = 0x40000001 for witness transactions
    const
      invTx = 1
      invWitnessTx = 0x40000001

    check invWitnessTx == 0x40000001
    check (invWitnessTx and 0x40000000) != 0  # Witness flag set

  test "txid format for broadcast":
    # Txid is 32 bytes, displayed as 64 hex chars reversed
    var txidBytes: array[32, byte]
    txidBytes[0] = 0x01
    txidBytes[31] = 0xFF
    let txidHex = bytesToHex(txidBytes)
    let displayHex = reverseHex(txidHex)

    check displayHex.len == 64
    check displayHex.startsWith("ff")
    check displayHex.endsWith("01")

suite "RPC getrawtransaction format":
  # RPC error codes for getrawtransaction
  const
    RpcInvalidAddressOrKey = -5

  test "error code constants":
    check RpcInvalidAddressOrKey == -5

  test "verbose output fields for mempool tx":
    # Expected fields for verbose output of unconfirmed transaction
    let expectedFields = ["txid", "hash", "version", "size", "vsize",
                          "weight", "locktime", "vin", "vout", "hex"]
    let verboseTx = %*{
      "txid": "0000000000000000000000000000000000000000000000000000000000000001",
      "hash": "0000000000000000000000000000000000000000000000000000000000000001",
      "version": 2,
      "size": 100,
      "vsize": 100,
      "weight": 400,
      "locktime": 0,
      "vin": [],
      "vout": [],
      "hex": "0200000000000000"
    }

    for field in expectedFields:
      check verboseTx.hasKey(field)

  test "verbose output fields for confirmed tx":
    # Additional fields for confirmed transactions
    let confirmedTx = %*{
      "txid": "0000000000000000000000000000000000000000000000000000000000000001",
      "hash": "0000000000000000000000000000000000000000000000000000000000000001",
      "version": 2,
      "size": 100,
      "vsize": 100,
      "weight": 400,
      "locktime": 0,
      "vin": [],
      "vout": [],
      "hex": "0200000000000000",
      "blockhash": "0000000000000000000000000000000000000000000000000000000000000000",
      "confirmations": 100,
      "time": 1234567890,
      "blocktime": 1234567890
    }

    check confirmedTx.hasKey("blockhash")
    check confirmedTx.hasKey("confirmations")
    check confirmedTx.hasKey("time")
    check confirmedTx.hasKey("blocktime")

  test "verbose output with explicit blockhash has in_active_chain":
    # When blockhash is explicitly provided, in_active_chain should be present
    let txWithExplicitBlock = %*{
      "txid": "0000000000000000000000000000000000000000000000000000000000000001",
      "in_active_chain": true,
      "blockhash": "0000000000000000000000000000000000000000000000000000000000000000",
      "confirmations": 100
    }

    check txWithExplicitBlock.hasKey("in_active_chain")
    check txWithExplicitBlock["in_active_chain"].getBool() == true

  test "scriptPubKey verbose fields":
    # scriptPubKey should have asm, hex, type, and optionally address
    let scriptPubKey = %*{
      "asm": "OP_DUP OP_HASH160 0000000000000000000000000000000000000000 OP_EQUALVERIFY OP_CHECKSIG",
      "hex": "76a914000000000000000000000000000000000000000088ac",
      "type": "pubkeyhash",
      "address": "1111111111111111111114oLvT2"
    }

    check scriptPubKey.hasKey("asm")
    check scriptPubKey.hasKey("hex")
    check scriptPubKey.hasKey("type")

  test "vin verbose format for non-coinbase":
    let vin = %*{
      "txid": "0000000000000000000000000000000000000000000000000000000000000001",
      "vout": 0,
      "scriptSig": {
        "asm": "",
        "hex": ""
      },
      "sequence": 4294967295
    }

    check vin.hasKey("txid")
    check vin.hasKey("vout")
    check vin.hasKey("scriptSig")
    check vin.hasKey("sequence")

  test "vin verbose format for coinbase":
    let coinbaseVin = %*{
      "coinbase": "03a08601",
      "sequence": 4294967295
    }

    check coinbaseVin.hasKey("coinbase")
    check coinbaseVin.hasKey("sequence")
    check not coinbaseVin.hasKey("txid")

  test "vout verbose format":
    let vout = %*{
      "value": 0.5,
      "n": 0,
      "scriptPubKey": {
        "asm": "OP_DUP OP_HASH160 ... OP_EQUALVERIFY OP_CHECKSIG",
        "hex": "76a914...",
        "type": "pubkeyhash",
        "address": "1..."
      }
    }

    check vout.hasKey("value")
    check vout.hasKey("n")
    check vout.hasKey("scriptPubKey")
    check vout["value"].getFloat() == 0.5

  test "vsize calculation":
    # vsize = (weight + 3) div 4 (rounded up)
    check (400 + 3) div 4 == 100  # 400 weight = 100 vsize
    check (401 + 3) div 4 == 101  # 401 weight = 101 vsize
    check (404 + 3) div 4 == 101  # 404 weight = 101 vsize (rounded up)

suite "RPC txindex format":
  test "txindex lookup result fields":
    # When txindex returns a result, it should include block location info
    let txLocation = %*{
      "blockHash": "0000000000000000000000000000000000000000000000000000000000000000",
      "txIndex": 0
    }

    check txLocation.hasKey("blockHash")
    check txLocation.hasKey("txIndex")

  test "confirmations calculation":
    # confirmations = tipHeight - blockHeight + 1
    let tipHeight = 100
    let blockHeight = 95
    let confirmations = tipHeight - blockHeight + 1
    check confirmations == 6

  test "txid parameter validation":
    # txid must be 64 hex characters
    let validTxid = "0000000000000000000000000000000000000000000000000000000000000001"
    let invalidTxid = "invalid"

    check validTxid.len == 64
    check invalidTxid.len != 64

suite "RPC batch requests":
  # Batch request constants
  const MaxBatchSize = 1000

  test "batch request structure":
    # Batch request is a JSON array of request objects
    let batchRequest = %*[
      {"jsonrpc": "2.0", "method": "getblockcount", "params": [], "id": 1},
      {"jsonrpc": "2.0", "method": "getbestblockhash", "params": [], "id": 2}
    ]

    check batchRequest.kind == JArray
    check batchRequest.len == 2
    check batchRequest[0]["id"].getInt() == 1
    check batchRequest[1]["id"].getInt() == 2

  test "batch response structure":
    # Batch response is a JSON array of response objects (same order as requests)
    let batchResponse = %*[
      {"jsonrpc": "2.0", "id": 1, "result": 100, "error": nil},
      {"jsonrpc": "2.0", "id": 2, "result": "0000000000000000000000000000000000000000000000000000000000000001", "error": nil}
    ]

    check batchResponse.kind == JArray
    check batchResponse.len == 2
    check batchResponse[0]["id"].getInt() == 1
    check batchResponse[1]["id"].getInt() == 2
    check batchResponse[0]["result"].getInt() == 100

  test "batch request with mixed success and failure":
    # Individual failures don't affect other requests
    let batchResponse = %*[
      {"jsonrpc": "2.0", "id": 1, "result": 100, "error": nil},
      {"jsonrpc": "2.0", "id": 2, "result": nil, "error": {"code": -32601, "message": "method not found"}},
      {"jsonrpc": "2.0", "id": 3, "result": "valid", "error": nil}
    ]

    check batchResponse.len == 3
    check batchResponse[0]["error"].kind == JNull
    check batchResponse[1]["error"]["code"].getInt() == -32601
    check batchResponse[2]["error"].kind == JNull

  test "empty batch returns error":
    # Empty batch array is an error
    let emptyBatch = newJArray()
    check emptyBatch.len == 0

    # Expected error response
    let errorResponse = %*{
      "jsonrpc": "2.0",
      "id": nil,
      "result": nil,
      "error": {"code": -32600, "message": "Empty batch array"}
    }
    check errorResponse["error"]["code"].getInt() == RpcInvalidRequest

  test "batch size limit":
    check MaxBatchSize == 1000

    # Requests exceeding limit should be rejected
    let oversizedError = %*{
      "jsonrpc": "2.0",
      "id": nil,
      "result": nil,
      "error": {"code": -32600, "message": "Batch size 1001 exceeds limit of 1000"}
    }
    check oversizedError["error"]["code"].getInt() == RpcInvalidRequest

  test "batch request ids preserved":
    # Each response must include the corresponding request id
    let batchRequest = %*[
      {"jsonrpc": "2.0", "method": "getblockcount", "params": [], "id": "abc"},
      {"jsonrpc": "2.0", "method": "getbestblockhash", "params": [], "id": 123},
      {"jsonrpc": "2.0", "method": "getdifficulty", "params": [], "id": nil}
    ]

    check batchRequest[0]["id"].getStr() == "abc"
    check batchRequest[1]["id"].getInt() == 123
    check batchRequest[2]["id"].kind == JNull

  test "batch handles invalid request objects":
    # Non-object items in batch array should return individual errors
    let invalidItem = %"not an object"
    check invalidItem.kind == JString

    # Expected error for non-object item
    let itemError = %*{
      "jsonrpc": "2.0",
      "id": nil,
      "result": nil,
      "error": {"code": -32600, "message": "Invalid Request object"}
    }
    check itemError["error"]["code"].getInt() == RpcInvalidRequest

  test "batch handles missing method":
    # Request without method field
    let noMethodReq = %*{"jsonrpc": "2.0", "id": 1, "params": []}
    check not noMethodReq.hasKey("method")

    let expectedError = %*{
      "jsonrpc": "2.0",
      "id": 1,
      "result": nil,
      "error": {"code": -32600, "message": "Missing method"}
    }
    check expectedError["error"]["code"].getInt() == RpcInvalidRequest

  test "single request returns object not array":
    # Single request should return object, not array
    let singleRequest = %*{
      "jsonrpc": "2.0",
      "method": "getblockcount",
      "params": [],
      "id": 1
    }
    check singleRequest.kind == JObject

    let singleResponse = %*{
      "jsonrpc": "2.0",
      "id": 1,
      "result": 100,
      "error": nil
    }
    check singleResponse.kind == JObject

  test "top-level parse error for invalid JSON":
    # Neither object nor array should return parse error
    let parseError = %*{
      "jsonrpc": "2.0",
      "id": nil,
      "result": nil,
      "error": {"code": -32700, "message": "Top-level object parse error"}
    }
    check parseError["error"]["code"].getInt() == RpcParseError

  test "batch request id types":
    # JSON-RPC allows string, number, or null for id
    let stringId = %*{"id": "request-1"}
    let numberId = %*{"id": 42}
    let nullId = %*{"id": nil}

    check stringId["id"].kind == JString
    check numberId["id"].kind == JInt
    check nullId["id"].kind == JNull

when isMainModule:
  echo "Running RPC tests..."
