## Tor/I2P proxy support for private Bitcoin node operation
## SOCKS5 proxy for all outgoing connections
## Tor control port for hidden service creation
## I2P SAM bridge for I2P connectivity
##
## Reference: Bitcoin Core netbase.cpp (SOCKS5), torcontrol.cpp (Tor), i2p.cpp (I2P)
## RFC 1928 (SOCKS5), RFC 1929 (SOCKS5 username/password)

import std/[strformat, strutils, random, tables, base64, options, os]
import chronos
import chronicles

# Helper to read exactly N bytes (chronos doesn't have readExactly)
proc readExact*(transport: StreamTransport, n: int): Future[seq[byte]] {.async.} =
  ## Read exactly n bytes from transport, raises on EOF
  result = newSeq[byte](n)
  var pos = 0
  while pos < n:
    var buf: array[4096, byte]
    let toRead = min(n - pos, buf.len)
    let bytesRead = await transport.readOnce(addr buf[0], toRead)
    if bytesRead == 0:
      raise newException(IOError, "connection closed")
    copyMem(addr result[pos], addr buf[0], bytesRead)
    pos += bytesRead

const
  # SOCKS5 protocol constants (RFC 1928)
  Socks5Version* = 0x05'u8
  Socks5AuthNone* = 0x00'u8
  Socks5AuthUserPass* = 0x02'u8
  Socks5AuthNoAcceptable* = 0xFF'u8

  # SOCKS5 commands
  Socks5CmdConnect* = 0x01'u8
  Socks5CmdBind* = 0x02'u8
  Socks5CmdUdpAssoc* = 0x03'u8

  # SOCKS5 address types
  Socks5AtypIPv4* = 0x01'u8
  Socks5AtypDomain* = 0x03'u8
  Socks5AtypIPv6* = 0x04'u8

  # SOCKS5 reply codes
  Socks5ReplySuccess* = 0x00'u8
  Socks5ReplyGeneralFailure* = 0x01'u8
  Socks5ReplyNotAllowed* = 0x02'u8
  Socks5ReplyNetworkUnreachable* = 0x03'u8
  Socks5ReplyHostUnreachable* = 0x04'u8
  Socks5ReplyConnectionRefused* = 0x05'u8
  Socks5ReplyTTLExpired* = 0x06'u8
  Socks5ReplyCommandNotSupported* = 0x07'u8
  Socks5ReplyAddressTypeNotSupported* = 0x08'u8

  # Tor-specific SOCKS5 extended reply codes
  Socks5ReplyTorOnionNotFound* = 0xF0'u8
  Socks5ReplyTorOnionInvalid* = 0xF1'u8
  Socks5ReplyTorIntroFailed* = 0xF2'u8
  Socks5ReplyTorRendezvousFailed* = 0xF3'u8
  Socks5ReplyTorOnionPubkeyInvalid* = 0xF4'u8
  Socks5ReplyTorOnionDecryptFailed* = 0xF5'u8
  Socks5ReplyTorDataStreamClosed* = 0xF6'u8
  Socks5ReplyTorCircuitExited* = 0xF7'u8

  # SOCKS5 username/password auth version (RFC 1929)
  Socks5AuthVersion* = 0x01'u8

  # Timeouts (Bitcoin Core uses 20 seconds for Tor)
  Socks5RecvTimeout* = 20.seconds
  Socks5ConnectTimeout* = 60.seconds

  # I2P SAM constants
  I2PSamPort* = 7656'u16          # Default SAM port
  I2PDefaultPort* = 0'u16         # I2P doesn't use ports in the traditional sense
  I2PSamVersion* = "3.1"
  I2PSignatureType* = 7'u8        # EdDSA with SHA512
  I2PMaxMsgSize* = 65536
  I2PSamRecvTimeout* = 3.minutes  # SAM operations can be slow

  # Tor control port constants
  TorControlPort* = 9051'u16
  TorReplyOk* = 250
  TorSafeCookieServerKey* = "Tor safe cookie authentication server-to-controller hash"
  TorSafeCookieClientKey* = "Tor safe cookie authentication controller-to-server hash"

type
  ProxyType* = enum
    ptNone
    ptSocks5
    ptTor       # SOCKS5 with Tor-specific features
    ptI2P       # I2P SAM bridge

  ProxyCredentials* = object
    username*: string
    password*: string

  Socks5ProxyConfig* = object
    host*: string
    port*: uint16
    auth*: Option[ProxyCredentials]
    randomizeCredentials*: bool   # Tor stream isolation

  TorControlConfig* = object
    host*: string
    port*: uint16
    password*: string             # Control port password (optional)
    cookieFile*: string           # Cookie file path (optional)

  I2PSamConfig* = object
    host*: string
    port*: uint16
    privateKeyFile*: string
    transient*: bool              # If true, don't persist identity

  ProxyConfig* = object
    proxyType*: ProxyType
    socks5*: Socks5ProxyConfig
    torControl*: TorControlConfig
    i2pSam*: I2PSamConfig

  ProxyError* = object of CatchableError
  Socks5Error* = object of ProxyError
  TorControlError* = object of ProxyError
  I2PSamError* = object of ProxyError

  # SOCKS5 proxy connection
  Socks5Proxy* = ref object
    config*: Socks5ProxyConfig
    streamIsolationCounter*: int

  # I2P SAM session
  I2PSession* = ref object
    config*: I2PSamConfig
    controlSock*: StreamTransport
    sessionId*: string
    privateKey*: seq[byte]
    myAddr*: string               # Our .b32.i2p address

  # Tor hidden service
  TorHiddenService* = ref object
    config*: TorControlConfig
    controlSock*: StreamTransport
    serviceId*: string            # .onion address without suffix
    privateKey*: string
    reconnectTimeout*: float

# =============================================================================
# SOCKS5 Protocol Implementation (RFC 1928/1929)
# =============================================================================

proc socks5ReplyToString*(reply: uint8): string =
  ## Convert SOCKS5 reply code to human-readable string
  case reply
  of Socks5ReplySuccess: "success"
  of Socks5ReplyGeneralFailure: "general failure"
  of Socks5ReplyNotAllowed: "connection not allowed"
  of Socks5ReplyNetworkUnreachable: "network unreachable"
  of Socks5ReplyHostUnreachable: "host unreachable"
  of Socks5ReplyConnectionRefused: "connection refused"
  of Socks5ReplyTTLExpired: "TTL expired"
  of Socks5ReplyCommandNotSupported: "command not supported"
  of Socks5ReplyAddressTypeNotSupported: "address type not supported"
  of Socks5ReplyTorOnionNotFound: "onion service descriptor not found"
  of Socks5ReplyTorOnionInvalid: "onion service descriptor invalid"
  of Socks5ReplyTorIntroFailed: "onion service introduction failed"
  of Socks5ReplyTorRendezvousFailed: "onion service rendezvous failed"
  of Socks5ReplyTorOnionPubkeyInvalid: "onion service public key invalid"
  of Socks5ReplyTorOnionDecryptFailed: "onion service decrypt failed"
  of Socks5ReplyTorDataStreamClosed: "data stream closed"
  of Socks5ReplyTorCircuitExited: "circuit exited"
  else: "unknown error " & $reply

proc newSocks5Proxy*(host: string, port: uint16,
                      auth: Option[ProxyCredentials] = none(ProxyCredentials),
                      randomizeCredentials: bool = false): Socks5Proxy =
  Socks5Proxy(
    config: Socks5ProxyConfig(
      host: host,
      port: port,
      auth: auth,
      randomizeCredentials: randomizeCredentials
    ),
    streamIsolationCounter: 0
  )

proc generateStreamIsolationCredentials*(proxy: var Socks5Proxy): ProxyCredentials =
  ## Generate unique credentials for Tor stream isolation
  ## Each unique credential pair creates a new Tor circuit
  inc proxy.streamIsolationCounter
  let suffix = $proxy.streamIsolationCounter
  ProxyCredentials(
    username: "nimrod" & suffix,
    password: "nimrod" & suffix
  )

proc socks5Handshake*(transport: StreamTransport,
                       auth: Option[ProxyCredentials]): Future[void] {.async.} =
  ## Perform SOCKS5 handshake (method selection + optional authentication)
  ## Reference: RFC 1928 section 3, RFC 1929

  # Phase 1: Send method selection
  var methods: seq[byte]
  methods.add(Socks5Version)

  if auth.isSome:
    methods.add(2'u8)  # Number of methods
    methods.add(Socks5AuthNone)
    methods.add(Socks5AuthUserPass)
  else:
    methods.add(1'u8)  # Number of methods
    methods.add(Socks5AuthNone)

  let written = await transport.write(methods)
  if written != methods.len:
    raise newException(Socks5Error, "failed to send SOCKS5 methods")

  # Read method selection response
  let response = await transport.readExact(2)

  if response[0] != Socks5Version:
    raise newException(Socks5Error, "invalid SOCKS5 version in response: " & $response[0])

  let selectedMethod = response[1]

  if selectedMethod == Socks5AuthNoAcceptable:
    raise newException(Socks5Error, "SOCKS5 server rejected all authentication methods")

  # Phase 2: Authenticate if required
  if selectedMethod == Socks5AuthUserPass:
    if auth.isNone:
      raise newException(Socks5Error, "server requires authentication but none provided")

    let cred = auth.get()
    if cred.username.len > 255 or cred.password.len > 255:
      raise newException(Socks5Error, "username or password too long")

    var authReq: seq[byte]
    authReq.add(Socks5AuthVersion)
    authReq.add(uint8(cred.username.len))
    for c in cred.username:
      authReq.add(byte(c))
    authReq.add(uint8(cred.password.len))
    for c in cred.password:
      authReq.add(byte(c))

    let authWritten = await transport.write(authReq)
    if authWritten != authReq.len:
      raise newException(Socks5Error, "failed to send SOCKS5 auth request")

    # Read auth response
    let authResponse = await transport.readExact(2)

    if authResponse[1] != 0x00:
      raise newException(Socks5Error, "SOCKS5 authentication failed")

    debug "SOCKS5 authentication successful"

  elif selectedMethod != Socks5AuthNone:
    raise newException(Socks5Error, "unsupported SOCKS5 auth method: " & $selectedMethod)

proc socks5Connect*(transport: StreamTransport, host: string, port: uint16): Future[void] {.async.} =
  ## Send SOCKS5 CONNECT request
  ## Uses domain name type to delegate DNS resolution to proxy (privacy)
  ## Reference: RFC 1928 section 4

  if host.len > 255:
    raise newException(Socks5Error, "hostname too long for SOCKS5")

  # Build connect request
  var request: seq[byte]
  request.add(Socks5Version)
  request.add(Socks5CmdConnect)
  request.add(0x00'u8)  # Reserved

  # Use domain name type for privacy (let proxy resolve DNS)
  request.add(Socks5AtypDomain)
  request.add(uint8(host.len))
  for c in host:
    request.add(byte(c))

  # Port in network byte order (big-endian)
  request.add(uint8((port shr 8) and 0xFF))
  request.add(uint8(port and 0xFF))

  let written = await transport.write(request)
  if written != request.len:
    raise newException(Socks5Error, "failed to send SOCKS5 connect request")

  # Read response header (4 bytes minimum)
  let response = await transport.readExact(4)

  if response[0] != Socks5Version:
    raise newException(Socks5Error, "invalid SOCKS5 version in connect response")

  if response[1] != Socks5ReplySuccess:
    raise newException(Socks5Error, "SOCKS5 connect failed: " &
                       socks5ReplyToString(response[1]))

  # Read bound address (we don't use it but must consume it)
  let addrType = response[3]
  case addrType
  of Socks5AtypIPv4:
    discard await transport.readExact(6)  # 4 bytes IP + 2 bytes port
  of Socks5AtypIPv6:
    discard await transport.readExact(18)  # 16 bytes IP + 2 bytes port
  of Socks5AtypDomain:
    let lenByte = await transport.readExact(1)
    let domainLen = int(lenByte[0])
    discard await transport.readExact(domainLen + 2)  # domain + 2 bytes port
  else:
    raise newException(Socks5Error, "unknown SOCKS5 address type: " & $addrType)

  debug "SOCKS5 connect successful", host = host, port = port

proc connectThroughSocks5*(proxy: var Socks5Proxy, host: string, port: uint16,
                            timeout: Duration = Socks5ConnectTimeout): Future[StreamTransport] {.async.} =
  ## Connect to a remote host through the SOCKS5 proxy
  ## Returns a connected StreamTransport ready for use

  # Connect to the proxy
  let proxyAddr = initTAddress(proxy.config.host, Port(proxy.config.port))
  let transport = await connect(proxyAddr).wait(timeout)

  try:
    # Determine authentication credentials
    var auth = proxy.config.auth
    if proxy.config.randomizeCredentials:
      auth = some(proxy.generateStreamIsolationCredentials())

    # Perform SOCKS5 handshake and connect
    await socks5Handshake(transport, auth).wait(Socks5RecvTimeout)
    await socks5Connect(transport, host, port).wait(Socks5RecvTimeout)

    return transport
  except CatchableError:
    await transport.closeWait()
    raise

proc connectThroughSocks5IPv4*(proxy: var Socks5Proxy, ip: array[4, byte], port: uint16,
                                timeout: Duration = Socks5ConnectTimeout): Future[StreamTransport] {.async.} =
  ## Connect to an IPv4 address through the SOCKS5 proxy

  let proxyAddr = initTAddress(proxy.config.host, Port(proxy.config.port))
  let transport = await connect(proxyAddr).wait(timeout)

  try:
    var auth = proxy.config.auth
    if proxy.config.randomizeCredentials:
      auth = some(proxy.generateStreamIsolationCredentials())

    await socks5Handshake(transport, auth).wait(Socks5RecvTimeout)

    # Build IPv4 connect request
    var request: seq[byte]
    request.add(Socks5Version)
    request.add(Socks5CmdConnect)
    request.add(0x00'u8)  # Reserved
    request.add(Socks5AtypIPv4)
    for b in ip:
      request.add(b)
    request.add(uint8((port shr 8) and 0xFF))
    request.add(uint8(port and 0xFF))

    let written = await transport.write(request)
    if written != request.len:
      raise newException(Socks5Error, "failed to send SOCKS5 connect request")

    # Read and validate response (same as domain)
    let response = await transport.readExact(10)  # Version + reply + reserved + atyp + 4 IP + 2 port

    if response[0] != Socks5Version or response[1] != Socks5ReplySuccess:
      raise newException(Socks5Error, "SOCKS5 connect failed: " &
                         socks5ReplyToString(response[1]))

    return transport
  except CatchableError:
    await transport.closeWait()
    raise

# =============================================================================
# Tor Control Port Protocol
# =============================================================================

proc torControlSendCommand*(transport: StreamTransport, cmd: string): Future[void] {.async.} =
  ## Send a command to the Tor control port
  let data = cmd & "\r\n"
  let written = await transport.write(data)
  if written != data.len:
    raise newException(TorControlError, "failed to send Tor control command")

proc torControlReadReply*(transport: StreamTransport): Future[tuple[code: int, lines: seq[string]]] {.async.} =
  ## Read a Tor control port reply (handles multi-line responses)
  ## Returns status code and all response lines
  var lines: seq[string]
  var code = 0

  while true:
    var line = ""
    var buf = newSeq[byte](1)

    # Read until CRLF
    while true:
      let bytesRead = await transport.readOnce(addr buf[0], 1)
      if bytesRead == 0:
        raise newException(TorControlError, "connection closed")
      if buf[0] == byte('\n'):
        break
      if buf[0] != byte('\r'):
        line.add(char(buf[0]))

    if line.len < 4:
      raise newException(TorControlError, "invalid Tor control response: " & line)

    # Parse status code
    try:
      code = parseInt(line[0..2])
    except ValueError:
      raise newException(TorControlError, "invalid Tor control status code: " & line)

    # Add the data portion
    lines.add(line[4..^1])

    # Check continuation character
    let continuation = line[3]
    if continuation == ' ':
      # Last line
      break
    elif continuation == '-':
      # More lines coming
      continue
    elif continuation == '+':
      # Data line (intermediate)
      continue
    else:
      raise newException(TorControlError, "invalid continuation character: " & $continuation)

  return (code, lines)

proc torControlAuthenticate*(transport: StreamTransport,
                              password: string = "",
                              cookieFile: string = ""): Future[void] {.async.} =
  ## Authenticate with Tor control port
  ## Tries NULL auth first, then password, then cookie

  # Get PROTOCOLINFO to determine available auth methods
  await torControlSendCommand(transport, "PROTOCOLINFO 1")
  let (code, lines) = await torControlReadReply(transport)

  if code != TorReplyOk:
    raise newException(TorControlError, "PROTOCOLINFO failed: " & lines.join(" "))

  # Parse available auth methods
  var authMethods: seq[string]
  var cookiePath = cookieFile

  for line in lines:
    if line.startsWith("AUTH METHODS="):
      let methodsPart = line.split(" ")[0]
      let methodsStr = methodsPart.split("=")[1]
      authMethods = methodsStr.split(",")
    if "COOKIEFILE=" in line:
      let parts = line.split("COOKIEFILE=")
      if parts.len > 1:
        var path = parts[1]
        if path.startsWith("\"") and path.endsWith("\""):
          path = path[1..^2]
        if cookiePath.len == 0:
          cookiePath = path

  # Try authentication methods in order of preference
  if "NULL" in authMethods:
    await torControlSendCommand(transport, "AUTHENTICATE")
    let (authCode, authLines) = await torControlReadReply(transport)
    if authCode == TorReplyOk:
      debug "Tor NULL authentication successful"
      return

  if "HASHEDPASSWORD" in authMethods and password.len > 0:
    await torControlSendCommand(transport, "AUTHENTICATE \"" & password & "\"")
    let (authCode, authLines) = await torControlReadReply(transport)
    if authCode == TorReplyOk:
      debug "Tor password authentication successful"
      return
    else:
      warn "Tor password authentication failed", error = authLines.join(" ")

  if ("COOKIE" in authMethods or "SAFECOOKIE" in authMethods) and cookiePath.len > 0:
    # Read cookie file
    if fileExists(cookiePath):
      let cookie = readFile(cookiePath)
      var cookieHex = ""
      for c in cookie:
        cookieHex.add(toHex(ord(c), 2))

      await torControlSendCommand(transport, "AUTHENTICATE " & cookieHex)
      let (authCode, authLines) = await torControlReadReply(transport)
      if authCode == TorReplyOk:
        debug "Tor cookie authentication successful"
        return
      else:
        warn "Tor cookie authentication failed", error = authLines.join(" ")

  raise newException(TorControlError, "all Tor authentication methods failed")

proc torControlAddOnion*(transport: StreamTransport,
                          targetHost: string, targetPort: uint16,
                          virtualPort: uint16,
                          privateKey: string = ""): Future[tuple[serviceId: string, key: string]] {.async.} =
  ## Create a Tor hidden service
  ## Returns the service ID (.onion address) and the private key

  var keyArg: string
  if privateKey.len > 0:
    keyArg = privateKey
  else:
    keyArg = "NEW:ED25519-V3"

  let cmd = fmt"ADD_ONION {keyArg} Port={virtualPort},{targetHost}:{targetPort}"
  await torControlSendCommand(transport, cmd)

  let (code, lines) = await torControlReadReply(transport)
  if code != TorReplyOk:
    raise newException(TorControlError, "ADD_ONION failed: " & lines.join(" "))

  var serviceId = ""
  var newKey = ""

  for line in lines:
    if line.startsWith("ServiceID="):
      serviceId = line.split("=")[1]
    elif line.startsWith("PrivateKey="):
      newKey = line.split("=", 1)[1]

  if serviceId.len == 0:
    raise newException(TorControlError, "ADD_ONION response missing ServiceID")

  # If we provided a key, use that; otherwise use the newly generated one
  if privateKey.len > 0:
    newKey = privateKey

  info "Created Tor hidden service", serviceId = serviceId & ".onion"

  return (serviceId, newKey)

proc torControlGetSocksPort*(transport: StreamTransport): Future[tuple[host: string, port: uint16]] {.async.} =
  ## Get Tor's SOCKS port from control port
  await torControlSendCommand(transport, "GETINFO net/listeners/socks")
  let (code, lines) = await torControlReadReply(transport)

  if code != TorReplyOk:
    raise newException(TorControlError, "GETINFO failed: " & lines.join(" "))

  for line in lines:
    if line.startsWith("net/listeners/socks="):
      var addrPart = line.split("=")[1]
      # Remove quotes
      addrPart = addrPart.strip(chars = {'"'})
      # Parse first address
      if addrPart.len > 0:
        let parts = addrPart.split(":")
        if parts.len >= 2:
          let host = parts[0]
          let port = uint16(parseInt(parts[1]))
          return (host, port)

  # Default to localhost:9050
  return ("127.0.0.1", 9050'u16)

proc newTorHiddenService*(config: TorControlConfig): TorHiddenService =
  TorHiddenService(
    config: config,
    reconnectTimeout: 1.0
  )

proc connectTorControl*(service: var TorHiddenService): Future[void] {.async.} =
  ## Connect to Tor control port
  let torAddr = initTAddress(service.config.host, Port(service.config.port))
  service.controlSock = await connect(torAddr)
  await torControlAuthenticate(service.controlSock,
                                service.config.password,
                                service.config.cookieFile)

proc createHiddenService*(service: var TorHiddenService,
                           targetHost: string, targetPort: uint16,
                           virtualPort: uint16): Future[string] {.async.} =
  ## Create a hidden service and return the .onion address
  let (serviceId, key) = await torControlAddOnion(service.controlSock,
                                                    targetHost, targetPort,
                                                    virtualPort, service.privateKey)
  service.serviceId = serviceId
  if service.privateKey.len == 0:
    service.privateKey = key

  return serviceId & ".onion"

# =============================================================================
# I2P SAM Protocol (Simple Anonymous Messaging)
# =============================================================================

# I2P Base64 uses different characters than standard Base64
proc i2pBase64Encode*(data: openArray[byte]): string =
  ## Encode to I2P Base64 (swaps +/- and /~)
  var std = encode(data)
  result = ""
  for c in std:
    case c
    of '+': result.add('-')
    of '/': result.add('~')
    else: result.add(c)

proc i2pBase64Decode*(data: string): seq[byte] =
  ## Decode from I2P Base64
  var std = ""
  for c in data:
    case c
    of '-': std.add('+')
    of '~': std.add('/')
    else: std.add(c)
  result = decode(std)

proc i2pSamSendRequest*(transport: StreamTransport, request: string): Future[void] {.async.} =
  ## Send a SAM request (terminated by newline)
  let data = request & "\n"
  let written = await transport.write(data)
  if written != data.len:
    raise newException(I2PSamError, "failed to send SAM request")
  debug "SAM request sent", request = request

proc i2pSamReadReply*(transport: StreamTransport): Future[Table[string, string]] {.async.} =
  ## Read and parse a SAM reply (key=value pairs)
  var line = ""
  var buf = newSeq[byte](1)

  # Read until newline
  while true:
    let bytesRead = await transport.readOnce(addr buf[0], 1)
    if bytesRead == 0:
      raise newException(I2PSamError, "connection closed")
    if buf[0] == byte('\n'):
      break
    line.add(char(buf[0]))

  debug "SAM reply received", reply = line

  # Parse key=value pairs
  result = initTable[string, string]()
  let parts = line.split(" ")

  for part in parts:
    if "=" in part:
      let kv = part.split("=", 1)
      if kv.len == 2:
        result[kv[0]] = kv[1]
    elif part.len > 0:
      # First word is the command echo
      if "COMMAND" notin result:
        result["COMMAND"] = part

proc newI2PSession*(config: I2PSamConfig): I2PSession =
  I2PSession(
    config: config,
    sessionId: ""
  )

proc i2pSamHello*(transport: StreamTransport): Future[void] {.async.} =
  ## Send SAM HELLO and verify response
  await i2pSamSendRequest(transport, fmt"HELLO VERSION MIN={I2PSamVersion} MAX={I2PSamVersion}")
  let reply = await i2pSamReadReply(transport)

  if reply.getOrDefault("RESULT") != "OK":
    raise newException(I2PSamError, "SAM HELLO failed: " & $reply)

  debug "SAM HELLO successful", version = reply.getOrDefault("VERSION")

proc i2pSamDestGenerate*(transport: StreamTransport): Future[tuple[pub: string, priv: seq[byte]]] {.async.} =
  ## Generate a new I2P destination
  await i2pSamSendRequest(transport, fmt"DEST GENERATE SIGNATURE_TYPE={I2PSignatureType}")
  let reply = await i2pSamReadReply(transport)

  if reply.getOrDefault("RESULT") != "OK":
    raise newException(I2PSamError, "DEST GENERATE failed: " & $reply)

  let pubB64 = reply.getOrDefault("PUB")
  let privB64 = reply.getOrDefault("PRIV")

  if pubB64.len == 0 or privB64.len == 0:
    raise newException(I2PSamError, "DEST GENERATE missing PUB or PRIV")

  return (pubB64, i2pBase64Decode(privB64))

proc i2pDestinationToAddress*(dest: openArray[byte]): string =
  ## Convert I2P destination to .b32.i2p address
  ## The address is Base32(SHA256(destination)).b32.i2p
  import nimcrypto/sha2

  var ctx: sha256
  ctx.init()
  ctx.update(dest)
  let hash = ctx.finish()

  # Base32 encode (lowercase, no padding)
  const Base32Chars = "abcdefghijklmnopqrstuvwxyz234567"
  var result = ""
  var buffer: uint64 = 0
  var bitsInBuffer = 0

  for b in hash.data:
    buffer = (buffer shl 8) or uint64(b)
    bitsInBuffer += 8

    while bitsInBuffer >= 5:
      bitsInBuffer -= 5
      result.add(Base32Chars[int((buffer shr bitsInBuffer) and 0x1F)])

  if bitsInBuffer > 0:
    result.add(Base32Chars[int((buffer shl (5 - bitsInBuffer)) and 0x1F)])

  return result & ".b32.i2p"

proc i2pExtractPublicDestination*(privateKey: openArray[byte]): seq[byte] =
  ## Extract public destination from private key
  ## The public destination is the first 387+ bytes (depending on certificate)
  const DestLenBase = 387
  const CertLenPos = 385

  if privateKey.len < DestLenBase:
    raise newException(I2PSamError, "private key too short")

  # Read certificate length (big-endian)
  let certLen = (uint16(privateKey[CertLenPos]) shl 8) or uint16(privateKey[CertLenPos + 1])
  let destLen = DestLenBase + int(certLen)

  if destLen > privateKey.len:
    raise newException(I2PSamError, "invalid destination format")

  result = @privateKey[0 ..< destLen]

proc connectSam*(session: var I2PSession): Future[void] {.async.} =
  ## Connect to I2P SAM bridge
  let samAddr = initTAddress(session.config.host, Port(session.config.port))
  session.controlSock = await connect(samAddr)
  await i2pSamHello(session.controlSock)

proc createSession*(session: var I2PSession): Future[void] {.async.} =
  ## Create an I2P streaming session
  randomize()
  session.sessionId = "nimrod" & $rand(999999)

  # Load or generate private key
  if session.config.privateKeyFile.len > 0 and
     not session.config.transient and
     fileExists(session.config.privateKeyFile):
    session.privateKey = cast[seq[byte]](readFile(session.config.privateKeyFile))
    debug "Loaded I2P private key from file", file = session.config.privateKeyFile
  elif not session.config.transient:
    # Generate new key
    let (_, priv) = await i2pSamDestGenerate(session.controlSock)
    session.privateKey = priv

    # Save to file
    if session.config.privateKeyFile.len > 0:
      let dir = parentDir(session.config.privateKeyFile)
      if dir.len > 0:
        createDir(dir)
      writeFile(session.config.privateKeyFile, cast[string](session.privateKey))
      debug "Saved I2P private key to file", file = session.config.privateKeyFile

  # Create session
  var cmd: string
  if session.config.transient:
    cmd = fmt"SESSION CREATE STYLE=STREAM ID={session.sessionId} DESTINATION=TRANSIENT " &
          fmt"SIGNATURE_TYPE={I2PSignatureType} i2cp.leaseSetEncType=4,0 " &
          "inbound.quantity=1 outbound.quantity=1"
  else:
    let destB64 = i2pBase64Encode(session.privateKey)
    cmd = fmt"SESSION CREATE STYLE=STREAM ID={session.sessionId} DESTINATION={destB64} " &
          "i2cp.leaseSetEncType=4,0 inbound.quantity=3 outbound.quantity=3"

  await i2pSamSendRequest(session.controlSock, cmd)
  let reply = await i2pSamReadReply(session.controlSock)

  if reply.getOrDefault("RESULT") != "OK":
    raise newException(I2PSamError, "SESSION CREATE failed: " & $reply)

  # For transient sessions, extract the destination from the reply
  if session.config.transient:
    let destB64 = reply.getOrDefault("DESTINATION")
    if destB64.len > 0:
      session.privateKey = i2pBase64Decode(destB64)

  # Compute our address
  let pubDest = i2pExtractPublicDestination(session.privateKey)
  session.myAddr = i2pDestinationToAddress(pubDest)

  info "I2P session created", sessionId = session.sessionId, address = session.myAddr

proc i2pConnect*(session: var I2PSession, destination: string): Future[StreamTransport] {.async.} =
  ## Connect to an I2P destination through SAM
  ## Destination should be a .b32.i2p address

  # First, need a new socket for the stream
  let samAddr = initTAddress(session.config.host, Port(session.config.port))
  let streamSock = await connect(samAddr)

  try:
    # Say hello on new socket
    await i2pSamHello(streamSock)

    # Look up the destination
    await i2pSamSendRequest(streamSock, fmt"NAMING LOOKUP NAME={destination}")
    let lookupReply = await i2pSamReadReply(streamSock)

    if lookupReply.getOrDefault("RESULT") != "OK":
      raise newException(I2PSamError, "NAMING LOOKUP failed: " & $lookupReply)

    let destB64 = lookupReply.getOrDefault("VALUE")
    if destB64.len == 0:
      raise newException(I2PSamError, "NAMING LOOKUP returned empty destination")

    # Connect
    await i2pSamSendRequest(streamSock, fmt"STREAM CONNECT ID={session.sessionId} DESTINATION={destB64} SILENT=false")
    let connectReply = await i2pSamReadReply(streamSock)

    let resultCode = connectReply.getOrDefault("RESULT")
    if resultCode != "OK":
      if resultCode == "INVALID_ID":
        raise newException(I2PSamError, "session invalid, reconnect needed")
      elif resultCode in ["CANT_REACH_PEER", "TIMEOUT"]:
        raise newException(I2PSamError, "peer unreachable: " & resultCode)
      else:
        raise newException(I2PSamError, "STREAM CONNECT failed: " & $connectReply)

    debug "I2P connection established", destination = destination
    return streamSock

  except CatchableError:
    await streamSock.closeWait()
    raise

proc i2pAccept*(session: var I2PSession): Future[tuple[sock: StreamTransport, peer: string]] {.async.} =
  ## Accept an incoming I2P connection
  ## Returns the socket and the peer's .b32.i2p address

  # Need a new socket for accepting
  let samAddr = initTAddress(session.config.host, Port(session.config.port))
  let acceptSock = await connect(samAddr)

  try:
    await i2pSamHello(acceptSock)

    # Start accepting
    await i2pSamSendRequest(acceptSock, fmt"STREAM ACCEPT ID={session.sessionId} SILENT=false")
    let acceptReply = await i2pSamReadReply(acceptSock)

    if acceptReply.getOrDefault("RESULT") != "OK":
      raise newException(I2PSamError, "STREAM ACCEPT failed: " & $acceptReply)

    # Wait for incoming connection - read peer destination
    var peerDestB64 = ""
    var buf = newSeq[byte](1)

    while true:
      let bytesRead = await acceptSock.readOnce(addr buf[0], 1)
      if bytesRead == 0:
        raise newException(I2PSamError, "connection closed while waiting for peer")
      if buf[0] == byte('\n'):
        break
      peerDestB64.add(char(buf[0]))

    # Convert destination to address
    let peerDest = i2pBase64Decode(peerDestB64)
    let peerAddr = i2pDestinationToAddress(peerDest)

    debug "I2P connection accepted", peer = peerAddr
    return (acceptSock, peerAddr)

  except CatchableError:
    await acceptSock.closeWait()
    raise

# =============================================================================
# Unified Proxy Interface
# =============================================================================

proc isOnionAddress*(host: string): bool =
  ## Check if host is a .onion address
  host.endsWith(".onion")

proc isI2PAddress*(host: string): bool =
  ## Check if host is an I2P address
  host.endsWith(".i2p")

type
  ProxyManager* = ref object
    ## Manages proxy connections for multi-network support
    clearnetProxy*: Option[Socks5Proxy]  # Optional proxy for clearnet
    onionProxy*: Option[Socks5Proxy]     # Proxy for .onion (usually Tor SOCKS)
    i2pSession*: Option[I2PSession]       # I2P SAM session
    torService*: Option[TorHiddenService] # Tor hidden service for inbound

proc newProxyManager*(): ProxyManager =
  ProxyManager()

proc configureProxy*(pm: ProxyManager, host: string, port: uint16,
                      auth: Option[ProxyCredentials] = none(ProxyCredentials)) =
  ## Configure main SOCKS5 proxy for all connections
  pm.clearnetProxy = some(newSocks5Proxy(host, port, auth, randomizeCredentials = false))

proc configureOnionProxy*(pm: ProxyManager, host: string, port: uint16,
                           randomizeCredentials: bool = true) =
  ## Configure separate proxy for .onion connections (usually Tor)
  pm.onionProxy = some(newSocks5Proxy(host, port, none(ProxyCredentials), randomizeCredentials))

proc configureI2P*(pm: ProxyManager, host: string, port: uint16,
                    privateKeyFile: string, transient: bool = false) =
  ## Configure I2P SAM connection
  pm.i2pSession = some(newI2PSession(I2PSamConfig(
    host: host,
    port: port,
    privateKeyFile: privateKeyFile,
    transient: transient
  )))

proc configureTorControl*(pm: ProxyManager, host: string, port: uint16,
                           password: string = "", cookieFile: string = "") =
  ## Configure Tor control port for hidden service
  pm.torService = some(newTorHiddenService(TorControlConfig(
    host: host,
    port: port,
    password: password,
    cookieFile: cookieFile
  )))

proc initializeI2P*(pm: ProxyManager) {.async.} =
  ## Initialize I2P session (must be called before connecting)
  if pm.i2pSession.isSome:
    var session = pm.i2pSession.get()
    await session.connectSam()
    await session.createSession()
    pm.i2pSession = some(session)

proc initializeTorHiddenService*(pm: ProxyManager, bindHost: string,
                                  bindPort: uint16, virtualPort: uint16): Future[string] {.async.} =
  ## Initialize Tor hidden service, returns .onion address
  if pm.torService.isSome:
    var service = pm.torService.get()
    await service.connectTorControl()
    let onionAddr = await service.createHiddenService(bindHost, bindPort, virtualPort)
    pm.torService = some(service)
    return onionAddr
  else:
    raise newException(ProxyError, "Tor control not configured")

proc connectThroughProxy*(pm: ProxyManager, host: string, port: uint16): Future[StreamTransport] {.async.} =
  ## Connect to a remote host, using appropriate proxy based on address type
  if host.isOnionAddress():
    if pm.onionProxy.isSome:
      var proxy = pm.onionProxy.get()
      return await proxy.connectThroughSocks5(host, port)
    elif pm.clearnetProxy.isSome:
      var proxy = pm.clearnetProxy.get()
      return await proxy.connectThroughSocks5(host, port)
    else:
      raise newException(ProxyError, "no proxy configured for .onion address")

  elif host.isI2PAddress():
    if pm.i2pSession.isSome:
      var session = pm.i2pSession.get()
      return await session.i2pConnect(host)
    else:
      raise newException(ProxyError, "I2P not configured for .i2p address")

  else:
    # Clearnet address
    if pm.clearnetProxy.isSome:
      var proxy = pm.clearnetProxy.get()
      return await proxy.connectThroughSocks5(host, port)
    else:
      # Direct connection (no proxy)
      let directAddr = initTAddress(host, Port(port))
      return await connect(directAddr)

proc getI2PAddress*(pm: ProxyManager): Option[string] =
  ## Get our I2P address if configured
  if pm.i2pSession.isSome:
    return some(pm.i2pSession.get().myAddr)
  return none(string)

proc getTorOnionAddress*(pm: ProxyManager): Option[string] =
  ## Get our Tor hidden service address if configured
  if pm.torService.isSome and pm.torService.get().serviceId.len > 0:
    return some(pm.torService.get().serviceId & ".onion")
  return none(string)
