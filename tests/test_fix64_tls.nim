## FIX-64 — HTTPS/TLS termination on the REST listener.
##
## Closes the W119 G3 finding (`tests/test_w119_payjoin.nim`) that
## `src/rpc/rest.nim:1024` opened a plaintext `createStreamServer` and
## never wrapped it in TLS.  After FIX-64 the same listener accepts
## either plaintext HTTP (default, backward-compat) or HTTPS when the
## operator passes both `--rpc-tls-cert` and `--rpc-tls-key`.
##
## Coverage:
##   1. HTTPS round-trip with a self-signed RSA cert (full handshake +
##      `GET /rest/chaininfo.json`-style request → response).
##   2. HTTP backward-compat preserved when neither flag is set.
##   3. Setting only `--rpc-tls-cert` (or only `--rpc-tls-key`) → hard
##      startup error from `newRestServer` (no silent downgrade).
##   4. Cert/key path that does not exist → startup error.
##   5. Garbage PEM content → startup error.
##
## The test spawns the listener on an ephemeral high port (assigned by
## the test, not `0`-bind, because the existing `RestServer.start` API
## takes a `uint16`).  All TLS material is generated into a per-test
## tempdir with `openssl req -x509 -newkey rsa:2048 -nodes` and deleted
## on teardown.
##
## Reference:
##   bitcoin-core/src/httpserver.cpp — libevent + OpenSSL pattern.
##   BIP-78 §Protocol — HTTPS or .onion required for clearnet PayJoin.

import unittest2
import std/[os, osproc, strutils, random]
import chronos
import chronos/streams/[asyncstream, tlsstream]

import ../src/rpc/rest
import ../src/consensus/params

# Seed once at module load — guarantees a fresh port pick per process.
randomize()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# An ephemeral port picker: bind(0), read assigned port, close.  The
# small race between close and the test bind is acceptable because each
# test runs in isolation and the chance of collision with another local
# listener in the 1-line gap is vanishing.
proc pickEphemeralPort(): uint16 =
  # Use a process-local randomised high port instead of bind(0)/close —
  # the kernel may keep the close()'d socket in TIME_WAIT for a few
  # seconds, and the immediate rebind by `rest.start()` then hits
  # EADDRINUSE even though both sockets set `ReuseAddr`.  Picking a
  # fresh unbound port avoids the race entirely.
  uint16(20_000 + rand(40_000))

proc makeSelfSigned(tmpDir: string): tuple[cert: string, key: string] =
  ## Generate a 2048-bit RSA self-signed cert + PKCS#8 PEM key via
  ## openssl.  The chronos `TLSPrivateKey.init` PEM parser only accepts
  ## `PRIVATE KEY` blocks (PKCS#8); `-nodes -pkeyopt`/`pkey` would also
  ## work but `openssl req -x509 -newkey rsa:2048 -nodes` already emits
  ## a PKCS#8 unencrypted key by default in OpenSSL 3.x.
  let cert = tmpDir / "cert.pem"
  let key = tmpDir / "key.pem"
  let res = execCmdEx(
    "openssl req -x509 -newkey rsa:2048 -nodes -days 1 " &
    "-keyout " & key.quoteShell() & " " &
    "-out " & cert.quoteShell() & " " &
    "-subj \"/CN=localhost\" 2>/dev/null")
  doAssert res.exitCode == 0, "openssl failed: " & res.output
  (cert: cert, key: key)

# Mini in-process HTTPS client over chronos.  We do NOT add a real HTTP
# library to the test deps — the existing REST mini-server already
# speaks raw HTTP/1.1, so the test mirrors that.
proc httpsGet(host: string, port: uint16, path: string): Future[string] {.async.} =
  let ta = initTAddress(host, Port(port))
  let transp = await connect(ta)
  let mainReader = newAsyncStreamReader(transp)
  let mainWriter = newAsyncStreamWriter(transp)
  let tls = newTLSClientAsyncStream(
    mainReader, mainWriter,
    serverName = "",
    minVersion = TLSVersion.TLS12,
    maxVersion = TLSVersion.TLS12,
    flags = {TLSFlags.NoVerifyHost, TLSFlags.NoVerifyServerName})
  try:
    await handshake(tls)
    let req = "GET " & path & " HTTP/1.1\r\nHost: " & host & "\r\n" &
              "Connection: close\r\n\r\n"
    await AsyncStreamWriter(tls.writer).write(req)
    var buf = ""
    while not AsyncStreamReader(tls.reader).atEof():
      try:
        let line = await AsyncStreamReader(tls.reader).readLine(sep = "\r\n")
        buf.add(line & "\n")
        if line.len == 0:
          break
      except CatchableError:
        break
    return buf
  finally:
    try: await AsyncStreamReader(tls.reader).closeWait()
    except CatchableError: discard
    try: await AsyncStreamWriter(tls.writer).closeWait()
    except CatchableError: discard
    await mainReader.closeWait()
    await mainWriter.closeWait()
    await transp.closeWait()

# Same shape as httpsGet but plaintext — used by the backward-compat
# test to prove the listener still answers a vanilla HTTP/1.1 request
# when neither --rpc-tls-cert nor --rpc-tls-key is set.
proc httpGet(host: string, port: uint16, path: string): Future[string] {.async.} =
  let ta = initTAddress(host, Port(port))
  let transp = await connect(ta)
  let req = "GET " & path & " HTTP/1.1\r\nHost: " & host & "\r\n" &
            "Connection: close\r\n\r\n"
  discard await transp.write(req)
  var buf = ""
  while not transp.closed:
    try:
      let line = await transp.readLine()
      buf.add(line & "\n")
      if line.len == 0:
        break
    except CatchableError:
      break
  await transp.closeWait()
  return buf

# Minimal RestServer suitable for the round-trip tests: real cert + key,
# but `chainState`/`mempool` are stubs (the route we hit is the 404
# fall-through, which exercises the full request → response path
# without needing storage state).  The W116/W117/W118 test suites
# similarly mock these dependencies.
proc newTestRest(port: uint16,
                 certPath = "",
                 keyPath = ""): RestServer =
  let dataDir = getTempDir() / "nimrod-fix64-" & $port
  if not dirExists(dataDir):
    createDir(dataDir)
  # The REST handlers we exercise (404 fall-through) do not touch the
  # storage layer; passing nils mirrors the pattern in
  # test_w119_payjoin.nim and the other rest-touching test files.
  let params = mainnetParams()
  newRestServer(
    port = port,
    chainState = nil,
    mempool = nil,
    params = params,
    txIndex = nil,
    filterIndex = nil,
    tlsCertPath = certPath,
    tlsKeyPath = keyPath
  )

# ---------------------------------------------------------------------------
# G1 — HTTPS round-trip (self-signed cert)
# ---------------------------------------------------------------------------
suite "FIX-64 G1 HTTPS round-trip":

  test "HTTPS handshake + GET round-trip with self-signed RSA-2048 cert":
    let tmp = getTempDir() / "fix64-https-" & $getCurrentProcessId()
    if dirExists(tmp): removeDir(tmp)
    createDir(tmp)
    defer:
      try: removeDir(tmp)
      except CatchableError: discard

    let (cert, key) = makeSelfSigned(tmp)
    check fileExists(cert)
    check fileExists(key)

    let port = pickEphemeralPort()
    let rest = newTestRest(port, certPath = cert, keyPath = key)
    check rest.tlsEnabled
    check rest.tlsPrivateKey != nil
    check rest.tlsCertificate != nil
    check rest.tlsCertPath == cert
    check rest.tlsKeyPath == key

    # Run the server in a background future; tear it down after the
    # round-trip completes.
    asyncSpawn rest.start()

    # Tiny yield so the listener binds before we connect.
    waitFor sleepAsync(50.milliseconds)

    let resp = waitFor httpsGet("127.0.0.1", port, "/rest/no-such-endpoint")
    rest.stop()
    # The server `accept` loop won't exit until the next connection
    # attempt; trigger one to unblock the future cleanly.
    try:
      discard waitFor connect(initTAddress("127.0.0.1", Port(port)))
    except CatchableError: discard

    # 404 is the expected response from the route fall-through.  What we
    # are actually proving here is that a *parseable HTTP response* came
    # back over a TLS handshake — i.e. TLS termination works end-to-end.
    check resp.len > 0
    check resp.startsWith("HTTP/1.1")
    # Don't pin the exact status; the route table may grow.  We just
    # want a real response, not a TLS-handshake failure.
    # serverFut is asyncSpawn'd — it cleans up on rest.stop().

# ---------------------------------------------------------------------------
# G2 — Backward-compat: plaintext HTTP still works
# ---------------------------------------------------------------------------
suite "FIX-64 G2 HTTP backward-compat":

  test "RestServer with no TLS args still serves plaintext HTTP":
    let port = pickEphemeralPort()
    let rest = newTestRest(port)
    check not rest.tlsEnabled
    check rest.tlsPrivateKey == nil
    check rest.tlsCertificate == nil

    asyncSpawn rest.start()
    waitFor sleepAsync(50.milliseconds)

    let resp = waitFor httpGet("127.0.0.1", port, "/rest/no-such-endpoint")
    rest.stop()
    try:
      discard waitFor connect(initTAddress("127.0.0.1", Port(port)))
    except CatchableError: discard

    check resp.len > 0
    check resp.startsWith("HTTP/1.1")

# ---------------------------------------------------------------------------
# G3 — Mismatched flags → startup error (no silent downgrade)
# ---------------------------------------------------------------------------
suite "FIX-64 G3 cert/key pair mismatch":

  test "cert set, key empty → RestError at newRestServer":
    let tmp = getTempDir() / "fix64-half-" & $getCurrentProcessId()
    if dirExists(tmp): removeDir(tmp)
    createDir(tmp)
    defer:
      try: removeDir(tmp)
      except CatchableError: discard
    let (cert, _) = makeSelfSigned(tmp)
    expect RestError:
      discard newTestRest(pickEphemeralPort(), certPath = cert, keyPath = "")

  test "key set, cert empty → RestError at newRestServer":
    let tmp = getTempDir() / "fix64-half2-" & $getCurrentProcessId()
    if dirExists(tmp): removeDir(tmp)
    createDir(tmp)
    defer:
      try: removeDir(tmp)
      except CatchableError: discard
    let (_, key) = makeSelfSigned(tmp)
    expect RestError:
      discard newTestRest(pickEphemeralPort(), certPath = "", keyPath = key)

# ---------------------------------------------------------------------------
# G4 — Invalid cert/key path → startup error
# ---------------------------------------------------------------------------
suite "FIX-64 G4 invalid cert/key path":

  test "cert path that does not exist → RestError":
    expect RestError:
      discard newTestRest(pickEphemeralPort(),
        certPath = "/nonexistent/fix64/cert.pem",
        keyPath = "/nonexistent/fix64/key.pem")

  test "garbage PEM content → RestError":
    let tmp = getTempDir() / "fix64-garbage-" & $getCurrentProcessId()
    if dirExists(tmp): removeDir(tmp)
    createDir(tmp)
    defer:
      try: removeDir(tmp)
      except CatchableError: discard
    let bogusCert = tmp / "bogus_cert.pem"
    let bogusKey = tmp / "bogus_key.pem"
    writeFile(bogusCert, "this is not a PEM certificate at all")
    writeFile(bogusKey, "neither is this")
    expect RestError:
      discard newTestRest(pickEphemeralPort(),
        certPath = bogusCert, keyPath = bogusKey)
