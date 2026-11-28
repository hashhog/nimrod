## The PayJoin G24 gate must decide on the HOST the sender will dial.
##
## BIP-78 §"Communicating with the receiver": the endpoint is https, or an
## http .onion address (Tor provides the authentication). The sender POSTs
## its fully signed Original PSBT to that endpoint, so a gate that waves a
## clearnet http:// URL through sends a signed transaction, its inputs and
## its change in plaintext to whoever is on the path.
##
## Before this fix `verifyPayJoinTlsCert` tested `.onion` as a substring
## of the whole URL, so `http://evil.test/p.onion` passed with the default
## (verifying) policy, and it tested loopback with `startsWith`, so with
## `ptsNoVerify` `http://127.0.0.1.evil.test/` passed as "loopback". The
## host predicate `isPayJoinOnionEndpoint` existed but the gate did not use
## it, and it split userinfo wrongly (`http://a.onion:1@evil.test/` dials
## evil.test). Core has no PayJoin; the reference here is BIP-78.
##
## The last suite runs the real sender pipeline against a local listener
## and checks that nothing reaches the socket: on the base commit the
## signed PSBT is POSTed in plaintext to a host whose only "onion" is the
## path.

import unittest2
import std/[options, strutils]
import chronos
import ../src/wallet/payjoin
import ../src/wallet/wallet
import ../src/wallet/psbt
import ../src/primitives/[types, serialize]
import ../src/crypto/address

const V3Onion = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"

proc noVerify(): PayJoinTlsConfig = PayJoinTlsConfig(policy: ptsNoVerify)

suite "cffix payjoin G24 gate decides on the host, not the URL string":

  test "rejects http clearnet host with .onion in the path (default policy)":
    check not verifyPayJoinTlsCert("http://evil.test/p.onion",
                                   defaultPayJoinTlsConfig())
    check not verifyPayJoinTlsCert("http://evil.test/x.onion/pj",
                                   defaultPayJoinTlsConfig())

  test "rejects http clearnet host with .onion in the query or fragment":
    check not verifyPayJoinTlsCert("http://evil.test/pj?h=a.onion",
                                   defaultPayJoinTlsConfig())
    check not verifyPayJoinTlsCert("http://evil.test/pj#a.onion",
                                   defaultPayJoinTlsConfig())

  test "rejects .onion as a subdomain label of a clearnet host":
    check not verifyPayJoinTlsCert("http://a.onion.evil.test/pj",
                                   defaultPayJoinTlsConfig())

  test "rejects .onion carried in userinfo (the dial target is after @)":
    check not verifyPayJoinTlsCert("http://a.onion@evil.test/pj",
                                   defaultPayJoinTlsConfig())
    check not verifyPayJoinTlsCert("http://a.onion:1@evil.test/pj",
                                   defaultPayJoinTlsConfig())

  test "rejects a non-http scheme even with an onion host":
    check not verifyPayJoinTlsCert("ftp://" & V3Onion & "/pj",
                                   defaultPayJoinTlsConfig())

  test "ptsNoVerify: rejects a public name that starts with a loopback string":
    check not verifyPayJoinTlsCert("http://127.0.0.1.evil.test/", noVerify())
    check not verifyPayJoinTlsCert("http://localhost.evil.test/pj", noVerify())
    check not verifyPayJoinTlsCert("http://localhostevil.test/pj", noVerify())

  test "ptsNoVerify: rejects loopback carried in userinfo":
    check not verifyPayJoinTlsCert("http://127.0.0.1@evil.test/", noVerify())
    check not verifyPayJoinTlsCert("http://localhost:80@evil.test/", noVerify())

  test "isPayJoinOnionEndpoint: userinfo before a clearnet host is not onion":
    check not isPayJoinOnionEndpoint("http://a.onion:1@evil.test/pj")
    check not isPayJoinOnionEndpoint("http://a.onion@evil.test/pj")

suite "cffix payjoin G24 gate controls (pass before and after)":

  test "accepts http://<onion>/ regardless of policy":
    check verifyPayJoinTlsCert("http://abcdefghijklmnopqrstuvwxyz.onion/",
                               defaultPayJoinTlsConfig())
    check verifyPayJoinTlsCert("http://" & V3Onion & ":80/pj?v=1",
                               defaultPayJoinTlsConfig())
    check verifyPayJoinTlsCert("http://" & V3Onion & "/pj", noVerify())
    check verifyPayJoinTlsCert("HTTP://" & V3Onion.toUpperAscii() & "/pj",
                               defaultPayJoinTlsConfig())

  test "accepts https://<onion>/":
    check verifyPayJoinTlsCert("https://" & V3Onion & "/pj",
                               defaultPayJoinTlsConfig())

  test "accepts https:// clearnet with a verifying policy":
    check verifyPayJoinTlsCert("https://payjoin.example/pj",
                               defaultPayJoinTlsConfig())
    check verifyPayJoinTlsCert("https://payjoin.example:8443/pj",
                               PayJoinTlsConfig(policy: ptsPinned))

  test "https:// clearnet with ptsNoVerify stays refused":
    check not verifyPayJoinTlsCert("https://payjoin.example/pj", noVerify())

  test "http:// clearnet stays refused under every policy":
    check not verifyPayJoinTlsCert("http://payjoin.example/pj",
                                   defaultPayJoinTlsConfig())
    check not verifyPayJoinTlsCert("http://payjoin.example/pj", noVerify())

  test "ptsNoVerify: exact loopback hosts pass":
    check verifyPayJoinTlsCert("http://127.0.0.1:1234/payjoin", noVerify())
    check verifyPayJoinTlsCert("http://localhost/payjoin", noVerify())
    check verifyPayJoinTlsCert("http://localhost:1234/payjoin", noVerify())
    check verifyPayJoinTlsCert("http://[::1]:8080/payjoin", noVerify())

  test "default policy: plain-http loopback is refused":
    check not verifyPayJoinTlsCert("http://127.0.0.1:1234/payjoin",
                                   defaultPayJoinTlsConfig())

  test "isPayJoinOnionEndpoint keeps its accepted forms":
    check isPayJoinOnionEndpoint("http://abcdef.onion:80/path?q=1")
    check isPayJoinOnionEndpoint("https://" & V3Onion & ":443/path")
    check isPayJoinOnionEndpoint("abcdef.onion:8443")
    check not isPayJoinOnionEndpoint("http://evil.test/p.onion")

# ---------------------------------------------------------------------------
# Production path: payjoinSenderRun must not put the PSBT on the wire.
# ---------------------------------------------------------------------------

const TestSeedByte = 0x42

proc makeSenderWallet(value: int64 = 500_000): Wallet =
  var seed: array[64, byte]
  for i in 0 ..< 64: seed[i] = byte(TestSeedByte xor (i * 7))
  var w = newWalletFromSeed(seed)
  w.addAccount(84, 0, 5)
  let key = w.accounts[0].externalKeys[0]
  let spk = scriptPubKeyForAddress(key.address)
  var idArr: array[32, byte]
  for i in 0 ..< 32: idArr[i] = byte((i + 13) and 0xff)
  w.addUtxo(OutPoint(txid: TxId(idArr), vout: 0'u32),
    TxOut(value: Satoshi(value), scriptPubKey: spk),
    height = 100'i32, keyPath = key.path,
    isInternal = false, isCoinbase = false)
  w

proc makeOriginalPsbt(sender: var Wallet): Psbt =
  ## Fully signed Original PSBT (same construction as test_fix66).
  let senderKey = sender.accounts[0].externalKeys[0]
  let senderSpk = scriptPubKeyForAddress(senderKey.address)
  var idArr: array[32, byte]
  for i in 0 ..< 32: idArr[i] = byte((i + 13) and 0xff)
  let op = OutPoint(txid: TxId(idArr), vout: 0'u32)
  let tx = Transaction(
    version: 2'i32,
    inputs: @[TxIn(prevOut: op, scriptSig: @[], sequence: 0xfffffffd'u32)],
    outputs: @[TxOut(value: Satoshi(200_000), scriptPubKey: senderSpk),
               TxOut(value: Satoshi(299_500), scriptPubKey: senderSpk)],
    witnesses: @[@[]],
    lockTime: 0'u32)
  var p = createPsbt(tx)
  p.updateInput(0, TxOut(value: Satoshi(500_000), scriptPubKey: senderSpk),
                isWitness = true)
  var workTx = tx
  let utxo = WalletUtxo(outpoint: op,
    output: TxOut(value: Satoshi(500_000), scriptPubKey: senderSpk),
    height: 100'i32, keyPath: senderKey.path,
    isInternal: false, isCoinbase: false)
  doAssert sender.signTransaction(workTx, @[utxo])
  p.inputs[0].finalScriptWitness = workTx.witnesses[0]
  var sigTx = p.tx.get()
  while sigTx.witnesses.len < sigTx.inputs.len:
    sigTx.witnesses.add(@[])
  sigTx.witnesses[0] = workTx.witnesses[0]
  p.tx = some(sigTx)
  p

type Sniffer = ref object
  server: StreamServer
  port: uint16
  received: string

proc startSniffer(): Sniffer =
  ## Plaintext listener on 127.0.0.1 that records whatever the sender
  ## writes, then hangs up. It stands in for "evil.test": the URL points
  ## its host at this socket and puts `.onion` only in the path.
  let s = Sniffer()
  proc onConn(server: StreamServer, t: StreamTransport) {.async: (raises: []).} =
    var buf: array[4096, byte]
    try:
      # Record until the client goes quiet for 500 ms or hangs up.
      while true:
        let n = await t.readOnce(addr buf[0], buf.len).wait(500.milliseconds)
        if n <= 0: break
        for i in 0 ..< n: s.received.add char(buf[i])
    except CatchableError:
      discard
    await t.closeWait()
  s.server = createStreamServer(initTAddress("127.0.0.1", Port(0)), onConn,
                                {ServerFlags.ReuseAddr})
  s.server.start()
  s.port = uint16(s.server.localAddress().port)
  s

proc stop(s: Sniffer) =
  s.server.stop()
  waitFor s.server.closeWait()

suite "cffix payjoin sender: no plaintext POST to a clearnet host":

  test "payjoinSenderRun refuses http://<clearnet>/p.onion before dialing":
    let sniff = startSniffer()
    defer: sniff.stop()
    var sender = makeSenderWallet()
    let original = makeOriginalPsbt(sender)
    let url = "http://127.0.0.1:" & $sniff.port & "/p.onion"
    let outcome = payjoinSenderRun(sender, original, endpointUrl = url,
      opts = PayJoinReceiveOptions(version: PAYJOIN_VERSION),
      timeoutMs = 3_000)
    # Let any in-flight server callback finish recording.
    waitFor sleepAsync(200.milliseconds)
    check not outcome.usedProposal
    check outcome.outcome == psoNetworkError
    check outcome.txid == original.tx.get().txid()
    check "G24" in outcome.receiverErrorMsg
    # Nothing — in particular not the signed PSBT — reached the socket.
    check sniff.received.len == 0
    check original.toBase64() notin sniff.received
