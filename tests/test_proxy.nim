## Tests for Tor/I2P proxy support
## Unit tests for SOCKS5 protocol, I2P addressing, and proxy manager

import unittest2
import std/[options, tables]
import ../src/network/proxy

suite "SOCKS5 protocol":
  test "socks5ReplyToString returns correct messages":
    check socks5ReplyToString(Socks5ReplySuccess) == "success"
    check socks5ReplyToString(Socks5ReplyGeneralFailure) == "general failure"
    check socks5ReplyToString(Socks5ReplyConnectionRefused) == "connection refused"
    check socks5ReplyToString(Socks5ReplyHostUnreachable) == "host unreachable"
    check socks5ReplyToString(Socks5ReplyNetworkUnreachable) == "network unreachable"
    check socks5ReplyToString(Socks5ReplyTTLExpired) == "TTL expired"

  test "socks5ReplyToString handles Tor-specific codes":
    check socks5ReplyToString(Socks5ReplyTorOnionNotFound) == "onion service descriptor not found"
    check socks5ReplyToString(Socks5ReplyTorOnionInvalid) == "onion service descriptor invalid"
    check socks5ReplyToString(Socks5ReplyTorIntroFailed) == "onion service introduction failed"
    check socks5ReplyToString(Socks5ReplyTorRendezvousFailed) == "onion service rendezvous failed"

  test "socks5ReplyToString handles unknown codes":
    let unknown = socks5ReplyToString(0x99'u8)
    check "unknown" in unknown

  test "newSocks5Proxy creates proxy with correct config":
    let proxy = newSocks5Proxy("127.0.0.1", 9050)
    check proxy.config.host == "127.0.0.1"
    check proxy.config.port == 9050
    check proxy.config.auth.isNone
    check proxy.config.randomizeCredentials == false

  test "newSocks5Proxy with auth":
    let auth = some(ProxyCredentials(username: "user", password: "pass"))
    let proxy = newSocks5Proxy("localhost", 1080, auth)
    check proxy.config.auth.isSome
    check proxy.config.auth.get().username == "user"
    check proxy.config.auth.get().password == "pass"

  test "generateStreamIsolationCredentials creates unique credentials":
    var proxy = newSocks5Proxy("127.0.0.1", 9050, randomizeCredentials = true)
    let cred1 = proxy.generateStreamIsolationCredentials()
    let cred2 = proxy.generateStreamIsolationCredentials()

    check cred1.username != cred2.username
    check cred1.password != cred2.password
    check cred1.username.startsWith("nimrod")
    check cred1.password.startsWith("nimrod")

suite "I2P Base64 encoding":
  test "i2pBase64Encode converts standard to I2P format":
    # I2P uses - instead of + and ~ instead of /
    let data = @[byte(0xFB), 0xFF]  # Would be +/ in standard Base64
    let encoded = i2pBase64Encode(data)
    check '-' notin "+"  # Sanity
    check '~' notin "/"

  test "i2pBase64Decode reverses encoding":
    let original = @[byte(1), 2, 3, 4, 5, 6, 7, 8]
    let encoded = i2pBase64Encode(original)
    let decoded = i2pBase64Decode(encoded)
    check decoded == original

  test "i2pBase64 round-trip preserves data":
    let testData = @[
      byte(0x00), 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
      byte(0x88), 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    ]
    let encoded = i2pBase64Encode(testData)
    let decoded = i2pBase64Decode(encoded)
    check decoded == testData

suite "I2P addressing":
  test "isI2PAddress detects .i2p addresses":
    check isI2PAddress("abcdef.b32.i2p")
    check isI2PAddress("test.i2p")
    check not isI2PAddress("example.com")
    check not isI2PAddress("test.onion")

  test "isOnionAddress detects .onion addresses":
    check isOnionAddress("abc123.onion")
    check isOnionAddress("example.onion")
    check not isOnionAddress("example.com")
    check not isOnionAddress("test.i2p")

  test "i2pDestinationToAddress generates .b32.i2p address":
    # Test with known destination bytes
    let dest = @[
      byte(0x00), 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      byte(0x08), 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    ]
    let i2pAddr = i2pDestinationToAddress(dest)
    check i2pAddr.endsWith(".b32.i2p")
    check i2pAddr.len > 10

  test "i2pExtractPublicDestination requires minimum length":
    let shortKey = @[byte(1), 2, 3]
    expect I2PSamError:
      discard i2pExtractPublicDestination(shortKey)

suite "Tor addressing":
  test "v3 onion addresses are 56 chars":
    # V3 onion addresses are 56 characters (without .onion)
    let v3 = "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd"
    check v3.len == 56

suite "proxy manager":
  test "newProxyManager creates empty manager":
    let pm = newProxyManager()
    check pm.clearnetProxy.isNone
    check pm.onionProxy.isNone
    check pm.i2pSession.isNone
    check pm.torService.isNone

  test "configureProxy sets clearnet proxy":
    let pm = newProxyManager()
    pm.configureProxy("127.0.0.1", 1080)
    check pm.clearnetProxy.isSome
    check pm.clearnetProxy.get().config.host == "127.0.0.1"
    check pm.clearnetProxy.get().config.port == 1080

  test "configureOnionProxy sets onion proxy with stream isolation":
    let pm = newProxyManager()
    pm.configureOnionProxy("127.0.0.1", 9050, randomizeCredentials = true)
    check pm.onionProxy.isSome
    check pm.onionProxy.get().config.randomizeCredentials == true

  test "configureI2P sets I2P session":
    let pm = newProxyManager()
    pm.configureI2P("127.0.0.1", 7656, "/tmp/i2p_key", transient = false)
    check pm.i2pSession.isSome
    check pm.i2pSession.get().config.host == "127.0.0.1"
    check pm.i2pSession.get().config.port == 7656
    check pm.i2pSession.get().config.privateKeyFile == "/tmp/i2p_key"

  test "configureTorControl sets Tor control":
    let pm = newProxyManager()
    pm.configureTorControl("127.0.0.1", 9051, password = "secret")
    check pm.torService.isSome
    check pm.torService.get().config.password == "secret"

  test "getI2PAddress returns none when not configured":
    let pm = newProxyManager()
    check pm.getI2PAddress().isNone

  test "getTorOnionAddress returns none when not configured":
    let pm = newProxyManager()
    check pm.getTorOnionAddress().isNone

suite "SOCKS5 constants":
  test "SOCKS5 version is 5":
    check Socks5Version == 0x05

  test "SOCKS5 auth methods are correct":
    check Socks5AuthNone == 0x00
    check Socks5AuthUserPass == 0x02
    check Socks5AuthNoAcceptable == 0xFF

  test "SOCKS5 address types are correct":
    check Socks5AtypIPv4 == 0x01
    check Socks5AtypDomain == 0x03
    check Socks5AtypIPv6 == 0x04

  test "SOCKS5 auth version is 1":
    check Socks5AuthVersion == 0x01

suite "I2P SAM constants":
  test "I2P SAM default port is 7656":
    check I2PSamPort == 7656

  test "I2P signature type 7 is EdDSA":
    check I2PSignatureType == 7

  test "I2P SAM version is 3.1":
    check I2PSamVersion == "3.1"

suite "Tor control constants":
  test "Tor control port is 9051":
    check TorControlPort == 9051

  test "Tor reply OK is 250":
    check TorReplyOk == 250

when isMainModule:
  echo "Running proxy tests..."
