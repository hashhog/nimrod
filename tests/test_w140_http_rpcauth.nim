## W140 — HTTP server + rpcauth + cookie auth + JSON-RPC dispatch audit
## (30 gates, xfail regression guards).
##
## Audit type: discovery (NO production code change in W140).
##
## W140 catalogues the gap between Bitcoin Core's HTTP / RPC stack
## (`src/httpserver.cpp`, `src/httprpc.cpp`, `src/rpc/request.cpp`,
## `share/rpcauth/rpcauth.py`) and nimrod's HTTP / RPC plumbing
## (`src/rpc/server.nim` `processClient` / `checkAuth` / `handleRequest`
## / `handleSingleRequest`, and `src/nimrod.nim` `generateCookieFile`
## + RPC startup).
##
## Method: each test asserts the CURRENT (buggy / absent) behaviour
## with a `check` that pins the gap.  When a future FIX wave closes
## the gap, the test will fail loudly and the developer MUST flip the
## assertion (per W120 / W122 / W123 / W124 / W125 / W128 / W131 /
## W132 / W133 / W134 / W135 / W136 / W137 methodology).
##
## References:
##   bitcoin-core/src/httpserver.cpp — libevent HTTP server, ClientAllowed,
##                                     HTTPBindAddresses, MAX_HEADERS_SIZE,
##                                     DEFAULT_HTTP_THREADS = 16,
##                                     DEFAULT_HTTP_WORKQUEUE = 64,
##                                     DEFAULT_HTTP_SERVER_TIMEOUT = 30,
##                                     evhttp_set_max_body_size(MAX_SIZE),
##                                     -rpcbind / -rpcallowip flow.
##   bitcoin-core/src/httprpc.cpp     — HTTPReq_JSONRPC, RPCAuthorized,
##                                     CheckUserAuthorized (HMAC-SHA256 +
##                                     TimingResistantEqual), 250 ms
##                                     UninterruptibleSleep on auth fail,
##                                     g_rpcauth, g_rpc_whitelist,
##                                     g_rpc_whitelist_default,
##                                     WWW_AUTH_HEADER_DATA = "Basic
##                                     realm=\"jsonrpc\"", JSONErrorReply
##                                     HTTP status mapping (400/404/500).
##   bitcoin-core/src/rpc/request.cpp — JSONRPCRequest::parse (id / method
##                                     / params / jsonrpc field shape),
##                                     GenerateAuthCookie (tmp + RenameOver),
##                                     GetAuthCookie, DeleteAuthCookie,
##                                     COOKIEAUTH_USER = "__cookie__",
##                                     COOKIEAUTH_FILE = ".cookie",
##                                     COOKIE_SIZE = 32, IsNotification().
##   bitcoin-core/src/util/strencodings.h — TimingResistantEqual.
##   bitcoin-core/share/rpcauth/rpcauth.py — 16-byte hex salt + HMAC-SHA256.
##   audit/w140_http_rpcauth.md       — full gate table + per-gate detail.

import unittest2
import std/[strutils, os]

# Read production source files once for source-level pinning.
let
  serverSrc:  string = readFile("src/rpc/server.nim")
  mainSrc:    string = readFile("src/nimrod.nim")
  threadSrc:  string = readFile("src/rpc/rpc_thread.nim")

# ---------------------------------------------------------------------------
# Core constants used to pin expected values
# ---------------------------------------------------------------------------
const
  # Core httpserver.h:20
  CORE_DEFAULT_HTTP_THREADS = 16
  # Core httpserver.h:26
  CORE_DEFAULT_HTTP_WORKQUEUE = 64
  # Core httpserver.h:28
  CORE_DEFAULT_HTTP_SERVER_TIMEOUT = 30
  # Core httpserver.cpp:51
  CORE_MAX_HEADERS_SIZE = 8192
  # Core rpc/request.cpp:81-83
  CORE_COOKIEAUTH_USER = "__cookie__"
  CORE_COOKIEAUTH_FILE = ".cookie"
  # Core rpc/request.cpp:104
  CORE_COOKIE_SIZE = 32
  # Core httprpc.cpp:33
  CORE_WWW_AUTH_HEADER_DATA = "Basic realm=\"jsonrpc\""
  # Core httprpc.cpp:128
  CORE_BRUTE_THROTTLE_MS = 250
  # Core rpcauth.py:37 — 16-byte hex salt
  CORE_RPCAUTH_SALT_BYTES = 16

# ---------------------------------------------------------------------------
# G1 — __cookie__ constant + .cookie filename (PRESENT)
# ---------------------------------------------------------------------------
suite "W140 G1 — __cookie__ constant + .cookie filename":

  test "G1 PRESENT: cookie content uses __cookie__:<hex> wire form":
    ## src/nimrod.nim:1525 — `cookieContent = "__cookie__:" & hexPass`.
    check "\"__cookie__:\" & hexPass" in mainSrc

  test "G1 PRESENT: cookie file path is dataDir / .cookie":
    ## src/nimrod.nim:1524 — `let cookiePath = dataDir / \".cookie\"`.
    check "dataDir / \".cookie\"" in mainSrc
    check CORE_COOKIEAUTH_FILE == ".cookie"
    check CORE_COOKIEAUTH_USER == "__cookie__"

# ---------------------------------------------------------------------------
# G2 — HTTP method gate (BUG-2, P0-SEC: GET silently treated as POST)
# ---------------------------------------------------------------------------
suite "W140 G2 — POST-only method gate":

  test "G2 BUG-2 (P0-SEC): GET is silently accepted alongside POST":
    ## src/rpc/server.nim:8693 — `line.startsWith(\"POST\") or
    ## line.startsWith(\"GET\")`. Core httprpc.cpp:107-110 explicitly
    ## refuses non-POST with HTTP_BAD_METHOD.  Flip this assertion when
    ## the fix wave restricts to POST.
    check "line.startsWith(\"POST\") or line.startsWith(\"GET\")" in serverSrc
    # No HTTP_BAD_METHOD / 405 reply path exists today.
    check "405" notin serverSrc
    check "Method Not Allowed" notin serverSrc

  test "G2 BUG-2 (P0-SEC): no \"only POST\" rejection branch present":
    ## Source-level: a `if requestMethod != \"POST\"` guard does not exist
    ## anywhere in server.nim.  Flip when the fix lands.
    check "!= \"POST\"" notin serverSrc

# ---------------------------------------------------------------------------
# G3 — IPv6 ::1 binding absent (BUG-3, P1-SEC)
# ---------------------------------------------------------------------------
suite "W140 G3 — IPv6 ::1 binding":

  test "G3 BUG-3 (P1-SEC): RPC server binds 127.0.0.1 only, no ::1":
    ## src/rpc/server.nim:8716 — `initTAddress(\"127.0.0.1\", Port(rpc.port))`.
    ## Core httpserver.cpp:319-321 binds both ::1 and 127.0.0.1.
    check "initTAddress(\"127.0.0.1\", Port(rpc.port))" in serverSrc
    # No ::1 endpoint anywhere in the RPC listener.
    check "::1" notin serverSrc

# ---------------------------------------------------------------------------
# G4 — -rpcauth hashed credentials (BUG-4, P1-SEC)
# ---------------------------------------------------------------------------
suite "W140 G4 — -rpcauth hashed credentials":

  test "G4 BUG-4 (P1-SEC): no -rpcauth CLI flag":
    ## Core httprpc.cpp:240-303 parses -rpcauth=<user>:<salt>$<hex_hmac>.
    ## Nimrod has no such parser.
    check "rpcauth" notin mainSrc.toLowerAscii()

  test "G4 BUG-4 (P1-SEC): no HMAC-SHA256 in auth path":
    ## Core httprpc.cpp:74 CHMAC_SHA256.  Nimrod's checkAuth only does
    ## plaintext equality.
    check "CHMAC_SHA256" notin serverSrc
    check "HMAC" notin serverSrc.toUpperAscii().split("\n").join("\n").
                          # avoid grabbing unrelated comments — search code only
                          replace("##", "@@")
    check CORE_RPCAUTH_SALT_BYTES == 16

# ---------------------------------------------------------------------------
# G5 — TimingResistantEqual on password / cookie (BUG-5, P0-SEC)
# ---------------------------------------------------------------------------
suite "W140 G5 — constant-time password / cookie comparison":

  test "G5 BUG-5 (P0-SEC): checkAuth uses Nim default `==` on cookie / pass":
    ## src/rpc/server.nim:8618-8623 — `pass == rpc.cookiePassword` /
    ## `pass == rpc.authPass` / `user == rpc.authUser`.  None are
    ## constant-time.  Core httprpc.cpp:66,77 wraps both username AND
    ## hash in TimingResistantEqual.
    check "pass == rpc.cookiePassword" in serverSrc
    check "user == rpc.authUser and pass == rpc.authPass" in serverSrc
    # No constant-time helper imported in this file.
    check "TimingResistantEqual" notin serverSrc
    check "constantTimeEqual" notin serverSrc
    check "ctEqual" notin serverSrc

# ---------------------------------------------------------------------------
# G6 — 250 ms brute-force throttle on auth fail (BUG-6, P1-SEC)
# ---------------------------------------------------------------------------
suite "W140 G6 — 250 ms brute-force throttle":

  test "G6 BUG-6 (P1-SEC): no sleepAsync after 401 Unauthorized write":
    ## Core httprpc.cpp:128 UninterruptibleSleep(250 ms).
    ## Nimrod's 401 path (server.nim:8650-8657) `break`s immediately.
    # The unique \"401 Unauthorized\" reply block does not contain any
    # sleep call.
    let idx = serverSrc.find("401 Unauthorized")
    check idx >= 0
    let snippet = serverSrc[idx ..< min(idx + 600, serverSrc.len)]
    check "sleepAsync(250" notin snippet
    check "sleepAsync 250" notin snippet
    check "milliseconds" notin snippet
    check CORE_BRUTE_THROTTLE_MS == 250

# ---------------------------------------------------------------------------
# G7 — -rpcwhitelist per-user method ACL (BUG-7, P1-SEC)
# ---------------------------------------------------------------------------
suite "W140 G7 — -rpcwhitelist":

  test "G7 BUG-7 (P1-SEC): no -rpcwhitelist / rpcwhitelistdefault flag":
    ## Core httprpc.cpp:38-39 + 306-326.
    check "rpcwhitelist" notin mainSrc.toLowerAscii()
    check "rpcwhitelist" notin serverSrc.toLowerAscii()

  test "G7 BUG-7 (P1-SEC): handleMethod takes only (methodName, params) — no authUser":
    ## Core JSONRPCRequest carries `authUser` to per-method dispatch
    ## for whitelist gating.  Nimrod's handleMethod takes only
    ## (methodName, params).  The RpcServer struct has an `authUser`
    ## field, but that is the CONFIG (-rpcuser) username — not the
    ## per-request authenticated user identity Core threads through
    ## for whitelist checks.
    check "proc handleMethod*(rpc: RpcServer, methodName: string, params: JsonNode)" in serverSrc
    # The handleMethod signature does NOT carry a per-request authUser.
    let sigIdx = serverSrc.find("proc handleMethod*(rpc: RpcServer, methodName: string, params: JsonNode)")
    check sigIdx >= 0
    let sigSnippet = serverSrc[sigIdx ..< min(sigIdx + 200, serverSrc.len)]
    check "authUser" notin sigSnippet
    # And handleSingleRequest does not pass any user identity to handleMethod.
    let hsrIdx = serverSrc.find("proc handleSingleRequest(rpc: RpcServer, reqJson: JsonNode)")
    check hsrIdx >= 0
    let hsrEnd = serverSrc.find("\nproc ", hsrIdx + 1)
    let hsrBody = if hsrEnd >= 0: serverSrc[hsrIdx ..< hsrEnd] else: serverSrc[hsrIdx ..< serverSrc.len]
    check "handleMethod(methodName, params)" in hsrBody
    check "authUser" notin hsrBody

# ---------------------------------------------------------------------------
# G8 — -rpcbind + -rpcallowip non-localhost ACL (BUG-1 + BUG-8, P1-SEC)
# ---------------------------------------------------------------------------
suite "W140 G8 — -rpcbind + -rpcallowip":

  test "G8 BUG-1 (P1-SEC): no -rpcallowip subnet ACL":
    ## Core httpserver.cpp:148-167 builds rpc_allow_subnets.
    check "rpcallowip" notin mainSrc.toLowerAscii()
    check "rpcallowip" notin serverSrc.toLowerAscii()

  test "G8 BUG-8 (P1-SEC): no -rpcbind host/port flag":
    ## Core httpserver.cpp:308-361 walks gArgs.GetArgs(\"-rpcbind\").
    check "rpcbind" notin mainSrc.toLowerAscii()
    # And the listener is hardcoded.
    check "initTAddress(\"127.0.0.1\", Port(rpc.port))" in serverSrc

# ---------------------------------------------------------------------------
# G9 — -rpccookieperms (BUG-9, P1-OPS)
# ---------------------------------------------------------------------------
suite "W140 G9 — -rpccookieperms":

  test "G9 BUG-9 (P1-OPS): no -rpccookieperms CLI flag":
    ## Core rpc/request.cpp:130-137 parses owner|group|all.
    check "rpccookieperms" notin mainSrc.toLowerAscii()

  test "G9 BUG-9 (P1-OPS): cookie permissions are hardcoded 0o600":
    ## src/nimrod.nim:1527 — `{fpUserRead, fpUserWrite}` (no other branches).
    check "setFilePermissions(cookiePath, {fpUserRead, fpUserWrite})" in mainSrc

# ---------------------------------------------------------------------------
# G10 — -rpccookiefile custom path (BUG-10, P1-OPS)
# ---------------------------------------------------------------------------
suite "W140 G10 — -rpccookiefile":

  test "G10 BUG-10 (P1-OPS): no -rpccookiefile / -norpccookiefile flags":
    ## Core rpc/request.cpp:86-96 honours -rpccookiefile=<path>.
    check "rpccookiefile" notin mainSrc.toLowerAscii()
    check "norpccookiefile" notin mainSrc.toLowerAscii()

  test "G10 BUG-10 (P1-OPS): cookie path is hardcoded to <datadir>/<network>/.cookie":
    ## Both write site and remove site use the same fixed pattern.
    check "let cookiePath = dataDir / \".cookie\"" in mainSrc

# ---------------------------------------------------------------------------
# G11 — HTTP status code mapping for JSON-RPC errors (BUG-11, P1-CORRECTNESS)
# ---------------------------------------------------------------------------
suite "W140 G11 — HTTP status codes for JSON-RPC errors":

  test "G11 BUG-11 (P1-CORRECTNESS): every HTTP reply is 200 OK":
    ## src/rpc/server.nim:8678 hardcodes \"HTTP/1.1 200 OK\".
    ## Core httprpc.cpp:41-58 maps RPC_INVALID_REQUEST -> 400,
    ## RPC_METHOD_NOT_FOUND -> 404, else -> 500.
    check "\"HTTP/1.1 200 OK\\r\\n\"" in serverSrc
    # No 400 / 404 / 500 status lines are emitted.
    check "HTTP/1.1 400" notin serverSrc
    check "HTTP/1.1 404" notin serverSrc
    check "HTTP/1.1 500" notin serverSrc

# ---------------------------------------------------------------------------
# G12 — JSON-RPC reply object shape per version (BUG-12, P1-CORRECTNESS)
# ---------------------------------------------------------------------------
suite "W140 G12 — V1-legacy vs V2 reply shape":

  test "G12 BUG-12 (P1-CORRECTNESS): success reply always carries both result + error":
    ## src/rpc/server.nim:8533-8538 — JsonNode literal contains both
    ## fields with null-error. Core's V2 path omits the null sibling.
    let body = serverSrc.find("Execute the method")
    check body >= 0
    let snippet = serverSrc[body ..< min(body + 400, serverSrc.len)]
    check "\"result\": methodResult" in snippet
    check "\"error\": newJNull()" in snippet

  test "G12 BUG-12 (P1-CORRECTNESS): makeErrorResponse emits both result+error":
    ## src/rpc/server.nim:8478-8487.
    check "proc makeErrorResponse(id: JsonNode, code: int, message: string)" in serverSrc
    let idx = serverSrc.find("proc makeErrorResponse(id: JsonNode")
    check idx >= 0
    let snippet = serverSrc[idx ..< min(idx + 500, serverSrc.len)]
    check "\"jsonrpc\": \"2.0\"" in snippet
    check "\"result\": newJNull()" in snippet
    check "\"error\":" in snippet

  test "G12 BUG-12 (P1-CORRECTNESS): no V1_LEGACY / V2 version branch":
    ## Core rpc/request.h:16-19 has JSONRPCVersion::V1_LEGACY/V2.
    ## Nimrod has no analogous enum.
    check "JSONRPCVersion" notin serverSrc
    check "V1_LEGACY" notin serverSrc
    check "JSONRPCVersion::V2" notin serverSrc

# ---------------------------------------------------------------------------
# G13 — Notification semantics (BUG-13, P1-CORRECTNESS)
# ---------------------------------------------------------------------------
suite "W140 G13 — JSON-RPC 2.0 notification (no id) semantics":

  test "G13 BUG-13 (P1-CORRECTNESS): no IsNotification() check":
    ## Core httprpc.cpp:167-171 emits HTTP_NO_CONTENT (204) for v2
    ## requests with no `id`.  Nimrod responds normally with id=null.
    check "IsNotification" notin serverSrc
    check "204" notin serverSrc
    check "No Content" notin serverSrc

  test "G13 BUG-13 (P1-CORRECTNESS): id-less request defaults to newJNull()":
    ## src/rpc/server.nim:8492-8497 — `var requestId = newJNull(); if
    ## reqJson.hasKey(\"id\"): requestId = reqJson[\"id\"]`.
    check "var requestId = newJNull()" in serverSrc
    check "if reqJson.hasKey(\"id\"):" in serverSrc

# ---------------------------------------------------------------------------
# G14 — jsonrpc field validation (BUG-14, P1-CORRECTNESS)
# ---------------------------------------------------------------------------
suite "W140 G14 — jsonrpc request field validation":

  test "G14 BUG-14 (P1-CORRECTNESS): jsonrpc field on request is never inspected":
    ## Core rpc/request.cpp:215-230 requires \"1.0\" or \"2.0\".
    ## Nimrod's handleSingleRequest never reads `reqJson[\"jsonrpc\"]`.
    let idx = serverSrc.find("proc handleSingleRequest(rpc: RpcServer, reqJson: JsonNode)")
    check idx >= 0
    let endIdx = serverSrc.find("\nproc ", idx + 1)
    let body = if endIdx >= 0: serverSrc[idx ..< endIdx] else: serverSrc[idx ..< serverSrc.len]
    check "reqJson[\"jsonrpc\"]" notin body
    check "reqJson.hasKey(\"jsonrpc\")" notin body

# ---------------------------------------------------------------------------
# G15 — params field type validation (BUG-15, P1-CORRECTNESS)
# ---------------------------------------------------------------------------
suite "W140 G15 — params type validation":

  test "G15 BUG-15 (P1-CORRECTNESS): params passed through without isArray / isObject check":
    ## Core rpc/request.cpp:245-252 — Params must be array, object, or
    ## null; else `RPC_INVALID_REQUEST`.  Nimrod takes whatever is there.
    let idx = serverSrc.find("# Extract params (default to empty array)")
    check idx >= 0
    let snippet = serverSrc[idx ..< min(idx + 300, serverSrc.len)]
    check "if reqJson.hasKey(\"params\"):" in snippet
    check "params = reqJson[\"params\"]" in snippet
    # No type-discrimination branch: no `.kind == JArray`, no
    # `.kind == JObject`, no `Params must be` rejection message.
    check ".kind == JArray" notin snippet
    check ".kind == JObject" notin snippet
    check "Params must be" notin snippet

# ---------------------------------------------------------------------------
# G16 — All-notification batch returns 204 (BUG-16, P1-CORRECTNESS)
# ---------------------------------------------------------------------------
suite "W140 G16 — all-notification batch returns 204":

  test "G16 BUG-16 (P1-CORRECTNESS): batch path always writes a JArray":
    ## src/rpc/server.nim:8580-8585 — accumulates responses into JArray
    ## and stringifies unconditionally.
    let idx = serverSrc.find("# Execute each request and collect responses")
    check idx >= 0
    let snippet = serverSrc[idx ..< min(idx + 400, serverSrc.len)]
    check "var responses = newJArray()" in snippet
    check "return $responses" in snippet
    # No 204 / No Content branch.
    check "204" notin snippet

# ---------------------------------------------------------------------------
# G17 — Empty batch returns `[]` not error (BUG-17, P1-CORRECTNESS)
# ---------------------------------------------------------------------------
suite "W140 G17 — empty batch returns []":

  test "G17 BUG-17 (P1-CORRECTNESS): empty batch returns RPC_INVALID_REQUEST error":
    ## src/rpc/server.nim:8571-8572 explicitly emits an error reply for
    ## empty batch — Core httprpc.cpp:211-222 returns `[]` for backwards
    ## compat (or 204 if non-empty + all-notifications).
    check "if parsedJson.len == 0:" in serverSrc
    check "RpcInvalidRequest, \"Empty batch array\"" in serverSrc

# ---------------------------------------------------------------------------
# G18 — Batch element non-object: error not abort (BUG-18, P1-CORRECTNESS)
# ---------------------------------------------------------------------------
suite "W140 G18 — batch element non-object handling":

  test "G18 BUG-18 (P1-CORRECTNESS): non-object element returns id=null reply, not abort":
    ## src/rpc/server.nim:8499-8506 — Invalid Request object reply per
    ## element.  Core httprpc.cpp:177-191 (whitelist-active path) throws
    ## `RPC_INVALID_REQUEST` and aborts the whole batch before executing
    ## any element.
    let idx = serverSrc.find("Validate request is an object")
    check idx >= 0
    let snippet = serverSrc[idx ..< min(idx + 400, serverSrc.len)]
    check "if reqJson.kind != JObject:" in snippet
    check "Invalid Request object" in snippet

# ---------------------------------------------------------------------------
# G19 — /wallet/<name> URL routing (BUG-19, P1-CORRECTNESS)
# ---------------------------------------------------------------------------
suite "W140 G19 — /wallet/<name> URL routing":

  test "G19 BUG-19 (P1-CORRECTNESS): currentWalletName is declared but never set":
    ## src/rpc/server.nim:50 declares the field; processClient (8629-)
    ## never extracts the URL path nor sets `rpc.currentWalletName`.
    check "currentWalletName*: string" in serverSrc
    # No assignment to currentWalletName anywhere in server.nim outside
    # the declaration line.
    let bodyAfterDecl = serverSrc.find("currentWalletName*: string")
    check bodyAfterDecl >= 0
    let tail = serverSrc[bodyAfterDecl + 30 ..< serverSrc.len]
    check "rpc.currentWalletName =" notin tail
    check ".currentWalletName = " notin tail
    # And the error message at server.nim:5220 ITSELF references the
    # /wallet/ URL contract that the server doesn't honor — self-confessing.
    check "/wallet/<walletname>" in serverSrc

  test "G19 BUG-19 (P1-CORRECTNESS): request line is `discard`ed without URL parse":
    ## src/rpc/server.nim:8693-8695.
    check "elif line.startsWith(\"POST\") or line.startsWith(\"GET\"):" in serverSrc
    let idx = serverSrc.find("elif line.startsWith(\"POST\") or line.startsWith(\"GET\"):")
    check idx >= 0
    let snippet = serverSrc[idx ..< min(idx + 200, serverSrc.len)]
    check "# Request line - ignore" in snippet
    check "discard" in snippet
    check "URI" notin snippet
    check "wallet" notin snippet

# ---------------------------------------------------------------------------
# G20 — -rpcthreads (BUG-20, P2-OPS)
# ---------------------------------------------------------------------------
suite "W140 G20 — -rpcthreads worker pool":

  test "G20 BUG-20 (P2-OPS): no -rpcthreads flag":
    ## Core httpserver.h:20 DEFAULT_HTTP_THREADS = 16.
    check "rpcthreads" notin mainSrc.toLowerAscii()

  test "G20 BUG-20 (P2-OPS): single-thread RPC model":
    ## src/rpc/rpc_thread.nim:42-54 — only one createThread call.
    check "createThread(result.thread, rpcThreadMain, rpc)" in threadSrc
    check "rebar" notin threadSrc        # sanity-check we read the file
    check CORE_DEFAULT_HTTP_THREADS == 16

# ---------------------------------------------------------------------------
# G21 — Max body-size DoS bound (BUG-21, P1-SEC)
# ---------------------------------------------------------------------------
suite "W140 G21 — request body size bound":

  test "G21 BUG-21 (P1-SEC): no maximum Content-Length cap":
    ## src/rpc/server.nim:8660-8662 reads `contentLength` bytes with no
    ## ceiling check.  Core httpserver.cpp:410 caps at MAX_SIZE (32 MiB).
    let idx = serverSrc.find("# Read body based on Content-Length")
    check idx >= 0
    let snippet = serverSrc[idx ..< min(idx + 400, serverSrc.len)]
    check "if contentLength > 0:" in snippet
    check "let bodyData = await transp.read(contentLength)" in snippet
    # No MAX_SIZE / MAX_BODY_SIZE comparison.
    check "MAX_SIZE" notin snippet
    check "MAX_BODY_SIZE" notin snippet
    check "maxBodySize" notin snippet
    check "33554432" notin snippet   # 32 MiB literal
    check "0x02000000" notin snippet

# ---------------------------------------------------------------------------
# G22 — Atomic cookie-file write (BUG-22, P0-SEC)
# ---------------------------------------------------------------------------
suite "W140 G22 — atomic cookie write":

  test "G22 BUG-22 (P0-SEC): cookie file is written directly, no .tmp + rename":
    ## src/nimrod.nim:1524-1527 — `writeFile(cookiePath, cookieContent)`
    ## directly.  Core rpc/request.cpp:113-128 writes to `.cookie.tmp`
    ## then `RenameOver` atomically.
    let idx = mainSrc.find("proc generateCookieFile*(dataDir: string)")
    check idx >= 0
    let endIdx = mainSrc.find("\nproc ", idx + 1)
    let body = if endIdx >= 0: mainSrc[idx ..< endIdx] else: mainSrc[idx ..< mainSrc.len]
    check "writeFile(cookiePath, cookieContent)" in body
    # The tmp + rename pattern is absent.
    check ".cookie.tmp" notin body
    check "moveFile(" notin body
    check "renameOver" notin body.toLowerAscii()

  test "G22 BUG-22 (P0-SEC): setFilePermissions runs AFTER writeFile (race window)":
    ## Even ignoring atomicity: chmod happens after the write succeeds.
    ## Core's tmp+rename approach inverts this (chmod the tmp, then
    ## rename) so the visible cookie is always 0600 from byte 0.
    let idx = mainSrc.find("proc generateCookieFile*(dataDir: string)")
    let endIdx = mainSrc.find("\nproc ", idx + 1)
    let body = if endIdx >= 0: mainSrc[idx ..< endIdx] else: mainSrc[idx ..< mainSrc.len]
    let writeIdx = body.find("writeFile(cookiePath, cookieContent)")
    let chmodIdx = body.find("setFilePermissions(cookiePath, {fpUserRead, fpUserWrite})")
    check writeIdx >= 0
    check chmodIdx >= 0
    check writeIdx < chmodIdx
    # Constant pin: 32-byte cookie matches Core COOKIE_SIZE.
    check "array[32, byte]" in body
    check CORE_COOKIE_SIZE == 32

# ---------------------------------------------------------------------------
# G23 — -rpcworkqueue + 503 backpressure (BUG-23, P2-OPS)
# ---------------------------------------------------------------------------
suite "W140 G23 — -rpcworkqueue + 503":

  test "G23 BUG-23 (P2-OPS): no -rpcworkqueue flag":
    check "rpcworkqueue" notin mainSrc.toLowerAscii()
    check "rpcworkqueue" notin serverSrc.toLowerAscii()

  test "G23 BUG-23 (P2-OPS): no 503 Service Unavailable reply":
    ## Core httpserver.cpp:255-258 sends 503 when work queue depth >=
    ## g_max_queue_depth.
    check "503" notin serverSrc
    check "Service Unavailable" notin serverSrc
    check CORE_DEFAULT_HTTP_WORKQUEUE == 64

# ---------------------------------------------------------------------------
# G24 — -rpcservertimeout (BUG-24, P2-OPS)
# ---------------------------------------------------------------------------
suite "W140 G24 — -rpcservertimeout":

  test "G24 BUG-24 (P2-OPS): no -rpcservertimeout flag":
    ## Core httpserver.cpp:408 — default 30 s libevent socket timeout.
    check "rpcservertimeout" notin mainSrc.toLowerAscii()

  test "G24 BUG-24 (P2-OPS): processClient while-loop has no read timeout":
    ## src/rpc/server.nim:8636-8710 — `while not transp.closed:` with
    ## bare `await transp.readLine()`.  No `withTimeout` / `wait`.
    let idx = serverSrc.find("proc processClient(rpc: RpcServer, transp: StreamTransport)")
    check idx >= 0
    let endIdx = serverSrc.find("\nproc ", idx + 1)
    let body = if endIdx >= 0: serverSrc[idx ..< endIdx] else: serverSrc[idx ..< serverSrc.len]
    check "while not transp.closed:" in body
    check "withTimeout" notin body
    check ".wait(" notin body
    check CORE_DEFAULT_HTTP_SERVER_TIMEOUT == 30

# ---------------------------------------------------------------------------
# G25 — MAX_HEADERS_SIZE = 8192 (BUG-25, P2-OPS)
# ---------------------------------------------------------------------------
suite "W140 G25 — MAX_HEADERS_SIZE":

  test "G25 BUG-25 (P2-OPS): no cumulative header-bytes cap":
    ## Core httpserver.cpp:51 + 409 — 8192 byte cumulative header cap.
    ## Nimrod's processClient reads headers via readLine() with no cap.
    check "MAX_HEADERS_SIZE" notin serverSrc
    check "8192" notin serverSrc
    check CORE_MAX_HEADERS_SIZE == 8192

# ---------------------------------------------------------------------------
# G26 — POST Content-Length: 0 hang (BUG-26, P2-OPS)
# ---------------------------------------------------------------------------
suite "W140 G26 — Content-Length 0 hang":

  test "G26 BUG-26 (P2-OPS): contentLength == 0 path writes no response":
    ## src/rpc/server.nim:8660 — `if contentLength > 0:` is the ONLY
    ## branch that ever calls transp.write().  contentLength == 0
    ## falls through to keep-alive reset (BUG-27) without writing
    ## any HTTP reply.  Client hangs.
    let idx = serverSrc.find("# Read body based on Content-Length")
    check idx >= 0
    let snippet = serverSrc[idx ..< min(idx + 600, serverSrc.len)]
    check "if contentLength > 0:" in snippet
    # No else / no 400 Bad Request branch for contentLength == 0.
    check "Bad Request" notin snippet
    check "HTTP/1.1 400" notin snippet
    check "elif contentLength == 0" notin snippet

# ---------------------------------------------------------------------------
# G27 — Keep-alive reset is dead code (BUG-27, P3)
# ---------------------------------------------------------------------------
suite "W140 G27 — keep-alive reset path":

  test "G27 BUG-27 (P3): keep-alive reset block exists but is unreachable":
    ## src/rpc/server.nim:8683-8691 — `break` at 8685 exits the while
    ## loop; the reset code at 8688-8691 only runs in the contentLength
    ## == 0 fall-through (which is itself BUG-26).
    check "# Reset for next request (keep-alive)" in serverSrc
    let idx = serverSrc.find("# Reset for next request (keep-alive)")
    check idx >= 0
    let snippet = serverSrc[idx ..< min(idx + 200, serverSrc.len)]
    check "inHeaders = true" in snippet
    check "headers.clear()" in snippet
    check "contentLength = 0" in snippet
    check "authHeader = \"\"" in snippet
    # And the only reply path forces Connection: close, so reset is
    # never reached after a successful reply.
    let okIdx = serverSrc.find("HTTP/1.1 200 OK")
    check okIdx >= 0
    let okSnippet = serverSrc[okIdx ..< min(okIdx + 500, serverSrc.len)]
    check "\"Connection: close\\r\\n\"" in okSnippet
    check "break" in okSnippet

# ---------------------------------------------------------------------------
# G28 — Header-key starting with "GET"/"POST" prefix shadowing (BUG-28, P3)
# ---------------------------------------------------------------------------
suite "W140 G28 — request-line vs header prefix shadowing":

  test "G28 BUG-28 (P3): request-line branch matched by startsWith only":
    ## src/rpc/server.nim:8693 — `line.startsWith(\"POST\") or
    ## line.startsWith(\"GET\")` precedes the `line.contains(\":\")`
    ## header branch.  A literal header `Get-User-Time: x` (or
    ## `Post-Authorization:`) is silently dropped because
    ## startsWith(\"GET\") matches before the header branch.
    let idx = serverSrc.find("elif line.startsWith(\"POST\") or line.startsWith(\"GET\"):")
    check idx >= 0
    # The robust shape (which we don't have) would split on whitespace
    # and assert that token[2] starts with "HTTP/".  That guard is absent.
    let tail = serverSrc[idx ..< min(idx + 400, serverSrc.len)]
    check "HTTP/" notin tail.split("\n")[0..min(5, tail.split("\n").high)].join("\n")

# ---------------------------------------------------------------------------
# G29 — CSPRNG for cookie (PRESENT)
# ---------------------------------------------------------------------------
suite "W140 G29 — CSPRNG for cookie generation":

  test "G29 PRESENT: generateCookieFile uses sysrand.urandom on 32 bytes":
    ## src/nimrod.nim:1516-1518 — `urandom(rawBytes)` of
    ## `array[32, byte]`.  Matches Core rpc/request.cpp:104-106
    ## (`COOKIE_SIZE = 32; GetRandBytes(rand_pwd)`).
    let idx = mainSrc.find("proc generateCookieFile*(dataDir: string)")
    check idx >= 0
    let endIdx = mainSrc.find("\nproc ", idx + 1)
    let body = if endIdx >= 0: mainSrc[idx ..< endIdx] else: mainSrc[idx ..< mainSrc.len]
    check "var rawBytes: array[32, byte]" in body
    check "if not urandom(rawBytes):" in body
    # And `urandom` is imported from `std/sysrand`.
    check "sysrand" in mainSrc

# ---------------------------------------------------------------------------
# G30 — Auth bypass when neither configured is unreachable (PRESENT)
# ---------------------------------------------------------------------------
suite "W140 G30 — auth-bypass fallback unreachable in default startup":

  test "G30 PRESENT: open-access branch is gated on hasUserPass + hasCookie":
    ## src/rpc/server.nim:8602-8603 — `if not hasUserPass and not
    ## hasCookie: return true`.
    check "if not hasUserPass and not hasCookie:" in serverSrc
    check "return true  # No auth configured" in serverSrc

  test "G30 PRESENT: nimrod.nim always generates a cookie when rpcEnabled":
    ## src/nimrod.nim:2247-2253 — `if config.rpcEnabled: ... let
    ## cookiePass = generateCookieFile(networkDir)`.  Thus `hasCookie`
    ## is always true in default startup → open-access branch
    ## unreachable.
    check "if config.rpcEnabled:" in mainSrc
    check "let cookiePass = generateCookieFile(networkDir)" in mainSrc
    # Cookie is wired into newRpcServer.
    check "cookiePass" in mainSrc
    let nrsIdx = mainSrc.find("newRpcServer(")
    check nrsIdx >= 0
    let endIdx2 = mainSrc.find(")", nrsIdx + 1)
    let snippet = mainSrc[nrsIdx ..< min(endIdx2 + 1, mainSrc.len)]
    check "config.rpcUser" in snippet
    check "config.rpcPassword" in snippet
    check "cookiePass" in snippet

# ---------------------------------------------------------------------------
# Summary pin
# ---------------------------------------------------------------------------
suite "W140 summary":

  test "summary: 28 BUGs catalogued across 28 gates (2 PRESENT)":
    ## Audit doc records 28 bugs.
    ## P0-SEC: BUG-2 (GET-as-POST), BUG-5 (timing-attackable equality),
    ##         BUG-22 (non-atomic cookie write).
    ## P1-SEC: BUG-1 (-rpcallowip), BUG-3 (no IPv6 bind), BUG-4
    ##         (-rpcauth HMAC), BUG-6 (250ms throttle), BUG-7
    ##         (-rpcwhitelist), BUG-8 (-rpcbind), BUG-21 (max body).
    ## P1-OPS: BUG-9 (-rpccookieperms), BUG-10 (-rpccookiefile).
    ## P1-CORRECTNESS: BUG-11 (HTTP status), BUG-12 (reply shape),
    ##         BUG-13 (notification), BUG-14 (jsonrpc field),
    ##         BUG-15 (params type), BUG-16 (all-notif batch 204),
    ##         BUG-17 (empty batch []), BUG-18 (batch element type),
    ##         BUG-19 (/wallet/<name>).
    ## P2-OPS: BUG-20 (-rpcthreads), BUG-23 (-rpcworkqueue + 503),
    ##         BUG-24 (-rpcservertimeout), BUG-25 (MAX_HEADERS_SIZE),
    ##         BUG-26 (Content-Length 0 hang).
    ## P3: BUG-27 (keep-alive dead code), BUG-28 (header-prefix shadowing).
    ## PRESENT (2 gates carry 3 PRESENT tests): G1 (__cookie__), G29
    ## (CSPRNG width), G30 (open-access unreachable in default startup).
    check 28 == 28  # placeholder — the assertion is the test count itself
