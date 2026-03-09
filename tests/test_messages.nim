## Tests for P2P message serialization
## Round-trip tests for all message types

import std/strutils
import unittest2
import ../src/network/messages
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing

proc hexToBytes(s: string): seq[byte] =
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[i*2 .. i*2+1]))

suite "command encoding":
  test "commandToBytes null-pads short commands":
    let cmd = commandToBytes("version")
    check cmd[0] == byte('v')
    check cmd[1] == byte('e')
    check cmd[2] == byte('r')
    check cmd[3] == byte('s')
    check cmd[4] == byte('i')
    check cmd[5] == byte('o')
    check cmd[6] == byte('n')
    # Remaining bytes should be zero
    for i in 7 ..< 12:
      check cmd[i] == 0

  test "commandToBytes truncates long commands":
    let cmd = commandToBytes("verylongcommand")
    check cmd.len == 12
    check cmd[0] == byte('v')
    check cmd[11] == byte('m')  # 12th char (0-indexed 11) of "verylongcomm"

  test "bytesToCommand strips null padding":
    var cmd: array[12, byte]
    cmd[0] = byte('p')
    cmd[1] = byte('i')
    cmd[2] = byte('n')
    cmd[3] = byte('g')
    # Rest are zeros
    check bytesToCommand(cmd) == "ping"

  test "command round-trip":
    let commands = ["version", "verack", "ping", "pong", "addr", "inv",
                    "getdata", "notfound", "getblocks", "getheaders",
                    "headers", "block", "tx", "getaddr", "reject",
                    "sendheaders", "sendcmpct", "feefilter", "wtxidrelay",
                    "sendaddrv2"]
    for c in commands:
      let encoded = commandToBytes(c)
      let decoded = bytesToCommand(encoded)
      check decoded == c

suite "message header":
  test "header serialization round-trip":
    let magic: array[4, byte] = [0xf9'u8, 0xbe, 0xb4, 0xd9]  # Mainnet
    let payload = @[0x01'u8, 0x02, 0x03, 0x04]
    let checksum = computeChecksum(payload)

    let headerBytes = serializeMessageHeader(magic, "ping", uint32(payload.len), checksum)

    check headerBytes.len == 24

    var r = BinaryReader(data: headerBytes, pos: 0)
    let header = r.deserializeMessageHeader()

    check header.magic == magic
    check bytesToCommand(header.command) == "ping"
    check header.length == 4
    check header.checksum == checksum

  test "checksum computation":
    let payload = @[0x01'u8, 0x02, 0x03, 0x04]
    let checksum = computeChecksum(payload)

    # Checksum is first 4 bytes of double SHA256
    let fullHash = doubleSha256(payload)
    check checksum[0] == fullHash[0]
    check checksum[1] == fullHash[1]
    check checksum[2] == fullHash[2]
    check checksum[3] == fullHash[3]

  test "checksum verification":
    let payload = @[0x01'u8, 0x02, 0x03, 0x04]
    let checksum = computeChecksum(payload)

    var header = MessageHeader(
      magic: [0xf9'u8, 0xbe, 0xb4, 0xd9],
      command: commandToBytes("test"),
      length: uint32(payload.len),
      checksum: checksum
    )

    check verifyChecksum(header, payload) == true

    # Modify payload
    var badPayload = payload
    badPayload[0] = 0xFF
    check verifyChecksum(header, badPayload) == false

suite "VersionMsg":
  test "VersionMsg round-trip":
    let addrRecv = NetAddress(
      services: NodeNetwork or NodeWitness,
      ip: [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1],
      port: 8333
    )
    let addrFrom = NetAddress(
      services: NodeNetwork,
      ip: [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1],
      port: 8333
    )

    let msg = P2PMessage(kind: mkVersion, version: VersionMsg(
      version: ProtocolVersion,
      services: NodeNetwork or NodeWitness,
      timestamp: 1609459200,
      addrRecv: addrRecv,
      addrFrom: addrFrom,
      nonce: 0x1234567890ABCDEF'u64,
      userAgent: UserAgent,
      startHeight: 700000,
      relay: true
    ))

    let payload = serializePayload(msg)
    let decoded = deserializePayload("version", payload)

    check decoded.kind == mkVersion
    check decoded.version.version == ProtocolVersion
    check decoded.version.services == (NodeNetwork or NodeWitness)
    check decoded.version.timestamp == 1609459200
    check decoded.version.addrRecv.port == 8333
    check decoded.version.addrFrom.port == 8333
    check decoded.version.nonce == 0x1234567890ABCDEF'u64
    check decoded.version.userAgent == UserAgent
    check decoded.version.startHeight == 700000
    check decoded.version.relay == true

  test "VersionMsg wire format size":
    let msg = P2PMessage(kind: mkVersion, version: VersionMsg(
      version: ProtocolVersion,
      services: NodeNetwork,
      timestamp: 0,
      addrRecv: NetAddress(),
      addrFrom: NetAddress(),
      nonce: 0,
      userAgent: "/test/",
      startHeight: 0,
      relay: true
    ))

    let payload = serializePayload(msg)
    # version(4) + services(8) + timestamp(8) + addrRecv(26) + addrFrom(26) +
    # nonce(8) + userAgent(varint+str) + startHeight(4) + relay(1)
    # 4 + 8 + 8 + 26 + 26 + 8 + (1 + 6) + 4 + 1 = 92
    check payload.len == 92

suite "empty payload messages":
  test "verack round-trip":
    let msg = newVerack()
    let payload = serializePayload(msg)
    check payload.len == 0
    let decoded = deserializePayload("verack", payload)
    check decoded.kind == mkVerack

  test "getaddr round-trip":
    let msg = newGetAddr()
    let payload = serializePayload(msg)
    check payload.len == 0
    let decoded = deserializePayload("getaddr", payload)
    check decoded.kind == mkGetAddr

  test "sendheaders round-trip":
    let msg = newSendHeaders()
    let payload = serializePayload(msg)
    check payload.len == 0
    let decoded = deserializePayload("sendheaders", payload)
    check decoded.kind == mkSendHeaders

  test "wtxidrelay round-trip":
    let msg = newWtxidRelay()
    let payload = serializePayload(msg)
    check payload.len == 0
    let decoded = deserializePayload("wtxidrelay", payload)
    check decoded.kind == mkWtxidRelay

  test "sendaddrv2 round-trip":
    let msg = newSendAddrV2()
    let payload = serializePayload(msg)
    check payload.len == 0
    let decoded = deserializePayload("sendaddrv2", payload)
    check decoded.kind == mkSendAddrV2

suite "ping/pong":
  test "ping round-trip":
    let msg = newPing(0xDEADBEEFCAFEBABE'u64)
    let payload = serializePayload(msg)
    check payload.len == 8
    let decoded = deserializePayload("ping", payload)
    check decoded.kind == mkPing
    check decoded.pingNonce == 0xDEADBEEFCAFEBABE'u64

  test "pong round-trip":
    let msg = newPong(0x123456789ABCDEF0'u64)
    let payload = serializePayload(msg)
    check payload.len == 8
    let decoded = deserializePayload("pong", payload)
    check decoded.kind == mkPong
    check decoded.pongNonce == 0x123456789ABCDEF0'u64

suite "GetHeaders/GetBlocks":
  test "GetHeaders round-trip":
    var locator1: array[32, byte]
    var locator2: array[32, byte]
    var hashStop: array[32, byte]

    for i in 0 ..< 32:
      locator1[i] = byte(i)
      locator2[i] = byte(32 - i)
      hashStop[i] = byte(i * 2)

    let msg = newGetHeaders(ProtocolVersion, @[locator1, locator2], hashStop)
    let payload = serializePayload(msg)
    let decoded = deserializePayload("getheaders", payload)

    check decoded.kind == mkGetHeaders
    check decoded.getHeaders.version == ProtocolVersion
    check decoded.getHeaders.locatorHashes.len == 2
    check decoded.getHeaders.locatorHashes[0] == locator1
    check decoded.getHeaders.locatorHashes[1] == locator2
    check decoded.getHeaders.hashStop == hashStop

  test "GetBlocks round-trip":
    var locator: array[32, byte]
    var hashStop: array[32, byte]

    for i in 0 ..< 32:
      locator[i] = byte(i)

    let msg = newGetBlocks(ProtocolVersion, @[locator], hashStop)
    let payload = serializePayload(msg)
    let decoded = deserializePayload("getblocks", payload)

    check decoded.kind == mkGetBlocks
    check decoded.getBlocks.version == ProtocolVersion
    check decoded.getBlocks.locatorHashes.len == 1
    check decoded.getBlocks.locatorHashes[0] == locator
    check decoded.getBlocks.hashStop == hashStop

  test "GetHeaders wire format size":
    var hashStop: array[32, byte]
    let msg = newGetHeaders(ProtocolVersion, @[], hashStop)
    let payload = serializePayload(msg)
    # version(4) + count(1) + hashStop(32) = 37
    check payload.len == 37

suite "inv/getdata/notfound":
  test "inv round-trip":
    var hash1: array[32, byte]
    var hash2: array[32, byte]
    for i in 0 ..< 32:
      hash1[i] = byte(i)
      hash2[i] = byte(31 - i)

    let items = @[
      InvVector(invType: invTx, hash: hash1),
      InvVector(invType: invBlock, hash: hash2)
    ]

    let msg = newInv(items)
    let payload = serializePayload(msg)
    let decoded = deserializePayload("inv", payload)

    check decoded.kind == mkInv
    check decoded.invItems.len == 2
    check decoded.invItems[0].invType == invTx
    check decoded.invItems[0].hash == hash1
    check decoded.invItems[1].invType == invBlock
    check decoded.invItems[1].hash == hash2

  test "witness inv types":
    var hash: array[32, byte]

    let items = @[
      InvVector(invType: invWitnessTx, hash: hash),
      InvVector(invType: invWitnessBlock, hash: hash)
    ]

    let msg = newInv(items)
    let payload = serializePayload(msg)
    let decoded = deserializePayload("inv", payload)

    check decoded.invItems[0].invType == invWitnessTx
    check decoded.invItems[1].invType == invWitnessBlock

  test "getdata round-trip":
    var hash: array[32, byte]
    let items = @[InvVector(invType: invBlock, hash: hash)]

    let msg = newGetData(items)
    let payload = serializePayload(msg)
    let decoded = deserializePayload("getdata", payload)

    check decoded.kind == mkGetData
    check decoded.getData.len == 1
    check decoded.getData[0].invType == invBlock

  test "notfound round-trip":
    var hash: array[32, byte]
    let items = @[InvVector(invType: invTx, hash: hash)]

    let msg = P2PMessage(kind: mkNotFound, notFound: items)
    let payload = serializePayload(msg)
    let decoded = deserializePayload("notfound", payload)

    check decoded.kind == mkNotFound
    check decoded.notFound.len == 1

suite "headers message":
  test "headers round-trip":
    let header1 = BlockHeader(
      version: 1,
      prevBlock: BlockHash(default(array[32, byte])),
      merkleRoot: default(array[32, byte]),
      timestamp: 1231006505,
      bits: 0x1d00ffff,
      nonce: 2083236893
    )

    let header2 = BlockHeader(
      version: 0x20000000,
      prevBlock: BlockHash(default(array[32, byte])),
      merkleRoot: default(array[32, byte]),
      timestamp: 1609459200,
      bits: 0x17034567,
      nonce: 12345
    )

    let msg = newHeaders(@[header1, header2])
    let payload = serializePayload(msg)
    let decoded = deserializePayload("headers", payload)

    check decoded.kind == mkHeaders
    check decoded.headers.len == 2
    check decoded.headers[0].version == 1
    check decoded.headers[0].timestamp == 1231006505
    check decoded.headers[0].bits == 0x1d00ffff'u32
    check decoded.headers[0].nonce == 2083236893'u32
    check decoded.headers[1].version == 0x20000000
    check decoded.headers[1].timestamp == 1609459200

  test "headers message includes dummy tx count":
    let header = BlockHeader(
      version: 1,
      prevBlock: BlockHash(default(array[32, byte])),
      merkleRoot: default(array[32, byte]),
      timestamp: 0,
      bits: 0,
      nonce: 0
    )

    let msg = newHeaders(@[header])
    let payload = serializePayload(msg)

    # count(1) + header(80) + dummy_tx_count(1) = 82
    check payload.len == 82

suite "addr message":
  test "addr round-trip":
    let addrs = @[
      TimestampedAddr(
        timestamp: 1609459200,
        address: NetAddress(
          services: NodeNetwork,
          ip: [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1],
          port: 8333
        )
      ),
      TimestampedAddr(
        timestamp: 1609459300,
        address: NetAddress(
          services: NodeWitness,
          ip: [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1],
          port: 18333
        )
      )
    ]

    let msg = P2PMessage(kind: mkAddr, addresses: addrs)
    let payload = serializePayload(msg)
    let decoded = deserializePayload("addr", payload)

    check decoded.kind == mkAddr
    check decoded.addresses.len == 2
    check decoded.addresses[0].timestamp == 1609459200
    check decoded.addresses[0].address.port == 8333
    check decoded.addresses[1].timestamp == 1609459300
    check decoded.addresses[1].address.port == 18333

suite "feefilter message":
  test "feefilter round-trip":
    let msg = newFeeFilter(1000)  # 1000 sat/kvB
    let payload = serializePayload(msg)
    check payload.len == 8
    let decoded = deserializePayload("feefilter", payload)

    check decoded.kind == mkFeeFilter
    check decoded.feeRate == 1000

suite "sendcmpct message":
  test "sendcmpct round-trip":
    let msg = P2PMessage(kind: mkSendCmpct, sendCmpct: SendCmpctMsg(
      announce: true,
      version: 2
    ))
    let payload = serializePayload(msg)
    check payload.len == 9  # 1 byte bool + 8 byte version
    let decoded = deserializePayload("sendcmpct", payload)

    check decoded.kind == mkSendCmpct
    check decoded.sendCmpct.announce == true
    check decoded.sendCmpct.version == 2

suite "reject message":
  test "reject round-trip":
    let msg = P2PMessage(kind: mkReject, reject: RejectMsg(
      message: "tx",
      code: 0x10,  # REJECT_INVALID
      reason: "bad-txns-inputs-missingorspent"
    ))
    let payload = serializePayload(msg)
    let decoded = deserializePayload("reject", payload)

    check decoded.kind == mkReject
    check decoded.reject.message == "tx"
    check decoded.reject.code == 0x10
    check decoded.reject.reason == "bad-txns-inputs-missingorspent"

suite "full message serialization":
  test "serializeMessage includes header and payload":
    let magic: array[4, byte] = [0xf9'u8, 0xbe, 0xb4, 0xd9]
    let msg = newPing(0x1234567890ABCDEF'u64)

    let fullMsg = serializeMessage(magic, msg)

    # Header (24) + payload (8) = 32
    check fullMsg.len == 32

    # Check magic
    check fullMsg[0] == 0xf9
    check fullMsg[1] == 0xbe
    check fullMsg[2] == 0xb4
    check fullMsg[3] == 0xd9

    # Check command
    check fullMsg[4] == byte('p')
    check fullMsg[5] == byte('i')
    check fullMsg[6] == byte('n')
    check fullMsg[7] == byte('g')

    # Check length (8 in little-endian)
    check fullMsg[16] == 8
    check fullMsg[17] == 0
    check fullMsg[18] == 0
    check fullMsg[19] == 0

    # Verify we can parse it back
    var r = BinaryReader(data: fullMsg, pos: 0)
    let header = r.deserializeMessageHeader()
    check bytesToCommand(header.command) == "ping"
    check header.length == 8

    let payload = r.readBytes(int(header.length))
    check verifyChecksum(header, payload)

    let decoded = deserializePayload("ping", payload)
    check decoded.pingNonce == 0x1234567890ABCDEF'u64

  test "verack full message":
    let magic: array[4, byte] = [0x0b'u8, 0x11, 0x09, 0x07]  # Testnet
    let msg = newVerack()

    let fullMsg = serializeMessage(magic, msg)

    # Header only, no payload
    check fullMsg.len == 24
    check fullMsg[16] == 0  # length = 0

suite "NetAddress encoding":
  test "port is big-endian":
    let netAddr = NetAddress(
      services: 1,
      ip: default(array[16, byte]),
      port: 8333
    )

    var w = BinaryWriter()
    w.writeNetAddress(netAddr)
    let data = w.data

    # Port bytes should be at offset 24 (services=8 + ip=16)
    # 8333 = 0x208D, big-endian is [0x20, 0x8D]
    check data[24] == 0x20
    check data[25] == 0x8D

  test "NetAddress round-trip":
    let original = NetAddress(
      services: NodeNetwork or NodeWitness or NodeNetworkLimited,
      ip: [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1],
      port: 18333
    )

    var w = BinaryWriter()
    w.writeNetAddress(original)

    var r = BinaryReader(data: w.data, pos: 0)
    let decoded = r.readNetAddress()

    check decoded.services == original.services
    check decoded.ip == original.ip
    check decoded.port == original.port

suite "message kind mapping":
  test "all message kinds map to commands":
    for kind in MessageKind:
      let cmd = messageKindToCommand(kind)
      check cmd.len > 0
      check cmd.len <= 12

      let backToKind = commandToMessageKind(cmd)
      check backToKind == kind

when isMainModule:
  echo "Running P2P message tests..."
