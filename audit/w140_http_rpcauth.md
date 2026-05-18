# W140 — HTTP server + rpcauth + cookie auth + JSON-RPC dispatch audit (nimrod)

Date: 2026-05-18
Audit type: discovery (NO production code change in W140).
Target:
  - `src/rpc/server.nim` HTTP / auth / JSON-RPC plumbing
    (`processClient` 8629-8712, `checkAuth` 8595-8627, `start` 8714-8730,
    `handleRequest` 8554-8593, `handleSingleRequest` 8489-8552,
    `makeErrorResponse` 8478-8487, batch / id / params parse).
  - `src/rpc/rpc_thread.nim` OS-thread launcher.
  - `src/nimrod.nim` (HTTP init wiring): `generateCookieFile` 1512-1529,
    cookie removal on shutdown 1474-1478, RPC startup 2247-2291,
    config flags (`--rpcuser`, `--rpcpassword`, `--norpc`, `--rpcport`).

Reference (Bitcoin Core):
  - `src/httpserver.cpp` + `src/httpserver.h` — libevent-driven HTTP
    server, `ClientAllowed` / `InitHTTPAllowList`, `HTTPBindAddresses`,
    `MAX_HEADERS_SIZE`, `DEFAULT_HTTP_THREADS=16`,
    `DEFAULT_HTTP_WORKQUEUE=64`, `DEFAULT_HTTP_SERVER_TIMEOUT=30`,
    `evhttp_set_max_body_size(http, MAX_SIZE)`, work-queue 503 fallback.
  - `src/httprpc.cpp` — `HTTPReq_JSONRPC`, `RPCAuthorized`,
    `CheckUserAuthorized` (HMAC-SHA256 / `TimingResistantEqual`),
    `InitRPCAuthentication`, `WWW_AUTH_HEADER_DATA =
    "Basic realm=\"jsonrpc\""`, 250 ms `UninterruptibleSleep` on auth fail,
    `g_rpcauth`, `g_rpc_whitelist`, `g_rpc_whitelist_default`,
    `JSONErrorReply` (HTTP 400/404/500 status mapping by code), 405 on
    non-POST, 403 on non-allowed IP.
  - `src/rpc/server_util.cpp` + `src/rpc/server.cpp` —
    `JSONRPCExec`, batch dispatch, `IsNotification()`,
    `m_json_version` V1_LEGACY vs V2 reply shape divergence.
  - `src/rpc/request.cpp` + `src/rpc/request.h` —
    `JSONRPCRequest::parse` (id / method / params / jsonrpc field
    validation; method-must-be-string, params-must-be-array-or-object,
    "jsonrpc field must be a string"), `GenerateAuthCookie`
    (atomic tmp + RenameOver, `-rpccookieperms`, `-rpccookiefile`),
    `GetAuthCookie`, `DeleteAuthCookie`,
    `COOKIEAUTH_USER = "__cookie__"`, `COOKIEAUTH_FILE = ".cookie"`,
    32-byte cookie size, `JSONRPCReplyObj` shape per version, `IsNotification`.
  - `share/rpcauth/rpcauth.py` — 16-byte hex salt, HMAC-SHA256 of password
    using salt as key, `username:salt$hex_hmac` config form.
  - `src/util/strencodings.h` — `TimingResistantEqual` (constant-time
    string compare for HMAC / cookie equality).
  - `src/init.cpp` — RPC subsystem init / shutdown ordering, libevent
    thread, `StartHTTPServer` / `InterruptHTTPServer` / `StopHTTPServer`.

BIPs: none directly (HTTP / auth / dispatch is non-consensus). Affects
operator-facing trust boundary (auth bypass, brute-force resistance, DoS,
TLS termination, ACL).

W140 is the **first** wave to audit nimrod's HTTP + auth surface
end-to-end against Core's `httpserver.cpp` / `httprpc.cpp`. Prior waves
(W124 G23 RPC cookie file presence; W125 RPC error-code parity; W119 +
FIX-64 REST/TLS termination; W84 / W83 RPC handler shape) inspected
adjacent surfaces but never enumerated the gates spanning HTTP request
parsing, ACL, IPv6 binding, rpcauth hash-based credentials,
rpcwhitelist per-user method ACL, timing-resistant equality,
brute-force throttle, HTTP status-code mapping for JSON-RPC errors,
JSON-RPC 2.0 notification semantics, `/wallet/<name>` URL routing,
keep-alive handling, max-body / max-headers DoS bounds, and atomic cookie
file write.

## Status

**BUGS FOUND — 28 distinct defects across 28 gates MISSING / PARTIAL /
WRONG (of 30). 2 gates PRESENT (Core-aligned).**

Of those:

  - **3 P0-SEC** — direct security / auth-surface compromise risk
    (BUG-2 GET silently accepted as POST → unauthenticated read of
    JSON-RPC over a single header-and-body-shaped GET; BUG-5
    plaintext-equality early-terminating password / cookie comparison
    leaks per-character timing — same class Core mitigated by
    `TimingResistantEqual`; BUG-22 cookie file write is non-atomic —
    crash mid-`writeFile` leaves a partial / empty `.cookie` that
    `bitcoin-cli` will read as valid empty-password credentials,
    bypassing auth on the next connect).
  - **9 P1-SEC / P1-OPS** — operator-facing security or hardening gaps
    (BUG-1 no `-rpcallowip` ACL; BUG-3 listener binds 127.0.0.1 only,
    no IPv6 `::1`; BUG-4 no `-rpcauth` hashed credentials; BUG-6 no
    250 ms brute-force throttle on auth fail; BUG-7 no `-rpcwhitelist`
    per-user method ACL; BUG-8 no `-rpcbind` for non-localhost; BUG-9
    no `-rpccookieperms` knob; BUG-10 no `-rpccookiefile` knob; BUG-21
    no max-body-size limit on request body — unbounded `transp.read`
    allocates whatever Content-Length declares).
  - **9 P1-CORRECTNESS** — JSON-RPC dispatch / wire-format parity gaps
    (BUG-11 HTTP status code is always 200 for RPC error responses —
    Core maps `RPC_INVALID_REQUEST` → 400, `RPC_METHOD_NOT_FOUND` →
    404, others → 500; BUG-12 reply object always emits both `result`
    and `error` fields even for v2 — Core's v2 omits the null sibling;
    BUG-13 `IsNotification()` semantics absent — id-less v2 requests
    still receive a response; BUG-14 `jsonrpc` field on request is not
    validated as "1.0" / "2.0" — any value silently accepted; BUG-15
    `params` is not validated as array-or-object — string / number
    silently accepted, dispatched, and JSON-stringified; BUG-16 batch
    of all-notifications still returns a non-empty array — Core
    returns HTTP 204; BUG-17 empty batch returns `-32600` error —
    Core returns `[]` for backward compat; BUG-18 batch element not
    an object dispatched as JNull-id error response — Core throws
    `RPC_INVALID_REQUEST` and aborts batch when whitelist is in use;
    BUG-19 `/wallet/<name>` URL prefix not extracted — `currentWalletName`
    field exists but is never set, so wallet selection by URL silently
    falls back to the default wallet).
  - **5 P2-OPS** — ops / config knobs absent (BUG-20 no `-rpcthreads`;
    BUG-23 no `-rpcworkqueue` + 503 backpressure; BUG-24 no
    `-rpcservertimeout` idle / read timeout; BUG-25 no `MAX_HEADERS_SIZE`
    enforcement — header lines unbounded; BUG-26 GET-method that lacks
    Content-Length yields connection hang and never sends a response —
    DoS by half-request).
  - **2 P3** — cosmetic / contract (BUG-27 keep-alive reset code at
    server.nim:8687-8691 is unreachable dead code because the
    bytes-on-wire path always `break`s on `Connection: close`; BUG-28
    request-line parser collapses arbitrary header keys starting with
    "POST" / "GET" — e.g. a literal `Get-User-Time:` request header
    is silently dropped because `startsWith("GET")` matches before the
    colon-containing-header branch).

## Gates / matrix

Order: each gate covers a distinct slice of Core's
`httpserver.cpp` + `httprpc.cpp` + `rpc/request.cpp` contract.

| # | Gate | Verdict |
|---|------|---------|
| G1  | `__cookie__` username constant + `.cookie` filename | PRESENT |
| G2  | HTTP method gate: POST only, GET → HTTP_BAD_METHOD | **BUG-2** (P0-SEC) |
| G3  | Listener binds both `::1` (IPv6) and `127.0.0.1` (IPv4) | **BUG-3** (P1-SEC) |
| G4  | `-rpcauth` hashed credentials (HMAC-SHA256, 16-byte hex salt) | **BUG-4** (P1-SEC) |
| G5  | `TimingResistantEqual` constant-time password / cookie compare | **BUG-5** (P0-SEC) |
| G6  | 250 ms `UninterruptibleSleep` brute-force throttle on auth fail | **BUG-6** (P1-SEC) |
| G7  | `-rpcwhitelist` + `-rpcwhitelistdefault` per-user method ACL | **BUG-7** (P1-SEC) |
| G8  | `-rpcbind` + `-rpcallowip` non-localhost ACL | **BUG-1** + **BUG-8** (P1-SEC) |
| G9  | `-rpccookieperms` (`owner` / `group` / `all`) | **BUG-9** (P1-OPS) |
| G10 | `-rpccookiefile` custom path | **BUG-10** (P1-OPS) |
| G11 | HTTP status mapping: `RPC_INVALID_REQUEST` → 400; `RPC_METHOD_NOT_FOUND` → 404; others → 500 (v1 legacy) | **BUG-11** (P1-CORRECTNESS) |
| G12 | JSON-RPC reply shape: v2 omits sibling null `result`/`error`; v1 legacy emits both | **BUG-12** (P1-CORRECTNESS) |
| G13 | JSON-RPC 2.0 notification (`id` absent) returns HTTP 204 / no body | **BUG-13** (P1-CORRECTNESS) |
| G14 | `jsonrpc` field validated as string == "1.0" or "2.0", else `RPC_INVALID_REQUEST` | **BUG-14** (P1-CORRECTNESS) |
| G15 | `params` validated as array-or-object-or-null, else `RPC_INVALID_REQUEST` | **BUG-15** (P1-CORRECTNESS) |
| G16 | All-notification batch returns HTTP 204 (no body) | **BUG-16** (P1-CORRECTNESS) |
| G17 | Empty batch `[]` returns `[]` (backward compat), not error | **BUG-17** (P1-CORRECTNESS) |
| G18 | Batch element not an object: `RPC_INVALID_REQUEST` thrown + reply | **BUG-18** (P1-CORRECTNESS) |
| G19 | `/wallet/<name>` URL prefix → `currentWalletName = UrlDecode(suffix)` | **BUG-19** (P1-CORRECTNESS) |
| G20 | `-rpcthreads` worker pool (default 16) | **BUG-20** (P2-OPS) |
| G21 | `evhttp_set_max_body_size(http, MAX_SIZE)` — body-size DoS bound | **BUG-21** (P1-SEC) |
| G22 | Cookie file write is atomic (`.cookie.tmp` + `RenameOver`) | **BUG-22** (P0-SEC) |
| G23 | `-rpcworkqueue` + 503 backpressure on queue saturation | **BUG-23** (P2-OPS) |
| G24 | `-rpcservertimeout` socket idle / read timeout (default 30s) | **BUG-24** (P2-OPS) |
| G25 | `MAX_HEADERS_SIZE = 8192` enforcement (per-request header total) | **BUG-25** (P2-OPS) |
| G26 | POST with Content-Length: 0 (or absent) writes an error reply, not hang | **BUG-26** (P2-OPS) |
| G27 | Keep-alive reset path executes (HTTP/1.1 default `Connection: keep-alive`) | **BUG-27** (P3) |
| G28 | Header-key starting with "GET" / "POST" is parsed as header, not request line | **BUG-28** (P3) |
| G29 | Cookie generation uses CSPRNG (`std/sysrand urandom`) — 32 bytes | PRESENT |
| G30 | Auth bypass when neither rpcuser/rpcpass nor cookie configured (`if not hasUserPass and not hasCookie: return true`) is unreachable in default startup because cookie is always generated | PRESENT |

## Detailed findings

### G1 — `__cookie__` constant + `.cookie` filename (PRESENT)

`src/nimrod.nim:1525`:
```nim
let cookieContent = "__cookie__:" & hexPass
let cookiePath = dataDir / ".cookie"
```
Matches Core `rpc/request.cpp:81-83` (`COOKIEAUTH_USER = "__cookie__"`,
`COOKIEAUTH_FILE = ".cookie"`). The 32-byte size (G29) also matches
Core `request.cpp:104` (`COOKIE_SIZE = 32`).

### G2 — HTTP method gate (BUG-2, P0-SEC)

`src/rpc/server.nim:8693`:
```nim
elif line.startsWith("POST") or line.startsWith("GET"):
  # Request line - ignore
  discard
```

**Critical**: GET is silently treated like POST. Core
`httprpc.cpp:107-110`:
```cpp
if (req->GetRequestMethod() != HTTPRequest::POST) {
    req->WriteReply(HTTP_BAD_METHOD, "JSONRPC server handles only POST requests");
    return false;
}
```

Combined with BUG-26 (no Content-Length → hang) the impact is bounded
in practice, but **a GET request with a Content-Length header and a
JSON body is dispatched identically to POST**. Concretely, a peer that
can reach the bound socket (loopback by default; widened by BUG-1 if
operator extends with iptables) can issue:

```
GET / HTTP/1.1
Authorization: Basic <cookie>
Content-Length: 53

{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo"}
```

…and nimrod will execute and reply 200 OK. This violates CSRF / cache
contracts (GET is supposed to be idempotent + cacheable) and is a
direct deviation from `RFC 9110 §9.3.1` plus Core's contract. **P0-SEC**
because clients / proxies / browsers may treat the response as
cacheable / CSRF-safe.

### G3 — IPv6 `::1` binding absent (BUG-3, P1-SEC)

`src/rpc/server.nim:8716`:
```nim
let ta = initTAddress("127.0.0.1", Port(rpc.port))
```

Single endpoint. Core `httpserver.cpp:319-321`:
```cpp
endpoints.emplace_back("::1", http_port);
endpoints.emplace_back("127.0.0.1", http_port);
```

On dual-stack hosts a client / `bitcoin-cli` defaulting to `::1` will
get `ECONNREFUSED` and fail before retrying `127.0.0.1`. Operator UX
divergence; not a direct compromise but breaks operator scripts. **P1-SEC**
because IPv6 / IPv4 ACL asymmetry is exactly the class of bug that
turns into a confused-deputy when an operator widens the bind in the
future.

### G4 — `-rpcauth` hashed credentials (BUG-4, P1-SEC)

Nimrod supports only `--rpcuser=USER --rpcpassword=PLAINTEXT`
(`src/nimrod.nim:509-512`). Core
`httprpc.cpp:240-303` parses `-rpcauth=<user>:<salt>$<hex_hmac>` lines
(form generated by `share/rpcauth/rpcauth.py`) and stores the salt /
HMAC in `g_rpcauth`. `CheckUserAuthorized`
(`httprpc.cpp:63-82`) HMAC-SHA256s the submitted password with the salt
and compares to the stored hash via `TimingResistantEqual`. Nimrod has
no `-rpcauth` flag, no HMAC table, no `CHMAC_SHA256` call in
auth.

This forces operators to either expose plaintext credentials on disk
(less safe; Core itself logs a warning: `LogWarning("The use of
rpcuser/rpcpassword is less secure…")` at `httprpc.cpp:270`) or run
cookie-only. Both are partial substitutes for the multi-user hashed
flow Core has supported since the v0.16 era.

### G5 — `TimingResistantEqual` (BUG-5, P0-SEC)

`src/rpc/server.nim:8618-8623`:
```nim
if user == "__cookie__" and hasCookie:
  return pass == rpc.cookiePassword
if hasUserPass:
  return user == rpc.authUser and pass == rpc.authPass
```

Three early-terminating equality comparisons. Nim's `==` on `string` is
not constant-time. Core
`httprpc.cpp:66-77` uses `TimingResistantEqual` (from
`util/strencodings.h:202-210`) explicitly for both username AND the
HMAC-derived hash. Per-character timing leaks a cookie character at a
time over a tight network loop; on a loopback or LAN attack surface
this is recoverable. **P0-SEC** because the cookie / password is the
ONLY auth boundary; once leaked, full RPC.

### G6 — 250 ms brute-force throttle (BUG-6, P1-SEC)

`src/rpc/server.nim:8650-8657` writes a `401 Unauthorized` and
`break`s with NO delay. Core
`httprpc.cpp:124-129`:
```cpp
LogWarning("ThreadRPCServer incorrect password attempt from %s", jreq.peerAddr);
UninterruptibleSleep(std::chrono::milliseconds{250});
```

The 250 ms sleep caps brute-force throughput at ~4 attempts/sec/conn.
Even on loopback this is the only line of defense before the 64-bit
hex cookie. Nimrod has no equivalent throttle.

### G7 — `-rpcwhitelist` per-user method ACL (BUG-7, P1-SEC)

Core
`httprpc.cpp:38-39,154-158,184-188,306-326` supports
`-rpcwhitelist=<user>:<method>,<method>…` and
`-rpcwhitelistdefault=0|1`. A whitelisted user only sees the
intersection across multiple `-rpcwhitelist=` lines for that user;
non-whitelisted users default to `g_rpc_whitelist_default`. Nimrod has
no such flag, no `g_rpc_whitelist`, no `authUser` plumbing to
`handleMethod`. A compromised cookie / password has full RPC.

### G8 — `-rpcbind` + `-rpcallowip` (BUG-1 + BUG-8, P1-SEC)

`src/rpc/server.nim:8716` hardcodes `127.0.0.1`. Core
`httpserver.cpp:148-167` builds `rpc_allow_subnets` from
`-rpcallowip`, and `httpserver.cpp:308-361` honours `-rpcbind=<host>` /
`-rpcbind=<host>:<port>`. Both together are mandatory to expose the
RPC over a non-loopback interface — Core refuses to widen the bind
without `-rpcallowip` (`httpserver.cpp:319-327`). Nimrod cannot widen
the bind at all without a source change. Bundled here because they're
two halves of the same ACL contract.

### G9 — `-rpccookieperms` (BUG-9, P1-OPS)

`src/nimrod.nim:1527` hardcodes `{fpUserRead, fpUserWrite}` (0600).
Core `rpc/request.cpp:130-137` parses `-rpccookieperms=owner|group|all`
and applies `fs::permissions(filepath, …)`. Nimrod operators running
a polkit / supervisor process under a different uid cannot grant
group-readable cookie auth without manual chmod.

### G10 — `-rpccookiefile` (BUG-10, P1-OPS)

Cookie path hardcoded to `<datadir>/<network>/.cookie`
(`nimrod.nim:2253-2254`). Core `request.cpp:86-96` honours
`-rpccookiefile=<path>` (and `-norpccookiefile` to disable).

### G11 — HTTP status code for JSON-RPC errors (BUG-11, P1-CORRECTNESS)

`src/rpc/server.nim:8678-8682`:
```nim
let httpResponse = "HTTP/1.1 200 OK\r\n" &
                  "Content-Type: application/json\r\n" &
                  ...
```
**Every** response (including parse errors, method-not-found,
internal errors) carries `200 OK`. Core
`httprpc.cpp:41-59`:
```cpp
int nStatus = HTTP_INTERNAL_SERVER_ERROR;  // 500
int code = objError.find_value("code").getInt<int>();
if (code == RPC_INVALID_REQUEST)
    nStatus = HTTP_BAD_REQUEST;            // 400
else if (code == RPC_METHOD_NOT_FOUND)
    nStatus = HTTP_NOT_FOUND;              // 404
```

Caveat: Core only does this for v1-legacy / non-V2 paths; in V2 the
HTTP code stays 200 by spec. Nimrod's blanket-200 matches the V2
shape but the wire still emits v1-shaped reply (both `result` and
`error`), so the combination is inconsistent.

### G12 — JSON-RPC reply object shape (BUG-12, P1-CORRECTNESS)

`src/rpc/server.nim:8478-8487`:
```nim
proc makeErrorResponse(id: JsonNode, code: int, message: string): string =
  $ %*{
    "jsonrpc": "2.0",
    "id": id,
    "result": newJNull(),
    "error": %*{...}
  }
```
And success path at `8533-8538`:
```nim
return %*{
  "jsonrpc": "2.0",
  "id": requestId,
  "result": methodResult,
  "error": newJNull()
}
```

Core `rpc/request.cpp:51-68`:
```cpp
UniValue JSONRPCReplyObj(UniValue result, UniValue error, std::optional<UniValue> id, JSONRPCVersion jsonrpc_version)
{
    UniValue reply(UniValue::VOBJ);
    if (jsonrpc_version == JSONRPCVersion::V2) reply.pushKV("jsonrpc", "2.0");
    if (error.isNull()) {
        reply.pushKV("result", std::move(result));
        if (jsonrpc_version == JSONRPCVersion::V1_LEGACY) reply.pushKV("error", NullUniValue);
    } else {
        if (jsonrpc_version == JSONRPCVersion::V1_LEGACY) reply.pushKV("result", NullUniValue);
        reply.pushKV("error", std::move(error));
    }
    if (id.has_value()) reply.pushKV("id", std::move(id.value()));
    return reply;
}
```

Nimrod always advertises `"jsonrpc": "2.0"` AND always emits both
sibling fields (one as null). For a strict JSON-RPC 2.0 client this
violates the spec ("Either the result member or error member MUST be
included, but both members MUST NOT be included"); for a v1-legacy
client the `"jsonrpc": "2.0"` advertises a contract nimrod doesn't honor.

### G13 — JSON-RPC 2.0 notification semantics (BUG-13, P1-CORRECTNESS)

Nimrod's `handleSingleRequest` defaults `requestId = newJNull()` when
`id` is absent (`server.nim:8492-8497`) and unconditionally returns a
response object. Core
`rpc/request.h:66`:
```cpp
[[nodiscard]] bool IsNotification() const { return !id.has_value() && m_json_version == JSONRPCVersion::V2; };
```
…and `httprpc.cpp:167-171`:
```cpp
if (jreq.IsNotification()) {
    // Even though we do execute notifications, we do not respond to them
    req->WriteReply(HTTP_NO_CONTENT);
    return true;
}
```
For a v2 request with no `id`, Core returns HTTP 204 with empty body.
Nimrod replies with a normal JSON object echoing `id: null`. Spec
violation; some libraries (e.g. `aiohttp_jsonrpc` clients) blow up.

### G14 — `jsonrpc` field validation (BUG-14, P1-CORRECTNESS)

Nimrod's `handleSingleRequest` never inspects the request `jsonrpc`
field. Core `rpc/request.cpp:215-230` requires it to be a string and
strictly "1.0" or "2.0":
```cpp
if (!jsonrpc_version.isStr())
    throw JSONRPCError(RPC_INVALID_REQUEST, "jsonrpc field must be a string");
if (jsonrpc_version.get_str() == "1.0")  { m_json_version = V1_LEGACY; }
else if (jsonrpc_version.get_str() == "2.0") { m_json_version = V2; }
else throw JSONRPCError(RPC_INVALID_REQUEST, "JSON-RPC version not supported");
```
Nimrod silently accepts `{"jsonrpc": 3, …}`, `{"jsonrpc": "3.0", …}`,
`{"jsonrpc": true, …}` — anything.

### G15 — `params` field validation (BUG-15, P1-CORRECTNESS)

`src/rpc/server.nim:8526-8529`:
```nim
var params = newJArray()
if reqJson.hasKey("params"):
  params = reqJson["params"]
```
Core `rpc/request.cpp:245-252`:
```cpp
const UniValue& valParams{request.find_value("params")};
if (valParams.isArray() || valParams.isObject())
    params = valParams;
else if (valParams.isNull())
    params = UniValue(UniValue::VARR);
else
    throw JSONRPCError(RPC_INVALID_REQUEST, "Params must be an array or object");
```
Nimrod silently passes a JSON string / number / bool through to
`handleMethod`. Concrete impact: a handler that expects an array index
will throw an internal error (`RpcInternalError`) instead of the
correct `RPC_INVALID_REQUEST`, leaking handler-internal details.

### G16 — All-notification batch returns 204 (BUG-16, P1-CORRECTNESS)

Core `httprpc.cpp:220-223`:
```cpp
if (reply.size() == 0 && valRequest.size() > 0) {
    req->WriteReply(HTTP_NO_CONTENT);
    return true;
}
```
Nimrod always writes the (possibly empty) array. Spec violation.

### G17 — Empty batch returns `[]` not error (BUG-17, P1-CORRECTNESS)

`src/rpc/server.nim:8571-8572`:
```nim
if parsedJson.len == 0:
  return makeErrorResponse(newJNull(), RpcInvalidRequest, "Empty batch array")
```
Core comment (`httprpc.cpp:211-219`):
```
Technically according to the JSON-RPC 2.0 spec, an empty batch request
should also return no response, However, if the batch request is
empty, it means the request did not contain any JSON-RPC version
numbers, so returning an empty response could break backwards
compatibility with old RPC clients relying on previous behavior. Return
an empty array instead of an empty response in this case to favor
being backwards compatible over complying with the JSON-RPC 2.0 spec
in this case.
```
Nimrod's chosen JSON-RPC error here is the third option (neither
backward-compat empty array nor spec-compliant 204).

### G18 — Batch element non-object handling (BUG-18, P1-CORRECTNESS)

`src/rpc/server.nim:8581-8583` dispatches each batch element to
`handleSingleRequest`, which returns an `RPC_INVALID_REQUEST` reply
with id=null. Core
`httprpc.cpp:177-191` (in whitelist-active path) throws
`RPC_INVALID_REQUEST` and aborts the whole batch BEFORE executing any
element (defense-in-depth so a malformed element can't induce
side-effects in adjacent valid ones). Nimrod's behavior is consistent
across cases but loses the whitelist-active short-circuit.

### G19 — `/wallet/<name>` URL routing (BUG-19, P1-CORRECTNESS)

`src/rpc/server.nim:50` declares
```nim
currentWalletName*: string           ## Current request's target wallet name
```
…with the docstring at `5198`: "Uses currentWalletName set by
processClient based on URL". **No code path sets it.** The HTTP
request line is `discard`ed at `server.nim:8693-8695` without parsing
URL. Core `wallet/rpc/util.cpp:56-58`:
```cpp
if (request.URI.starts_with(WALLET_ENDPOINT_BASE)) {
    wallet_name = UrlDecode(std::string_view{request.URI}.substr(WALLET_ENDPOINT_BASE.size()));
}
```
…with `WALLET_ENDPOINT_BASE = "/wallet/"`. Nimrod's wallet-RPC dispatch
falls back to the default wallet regardless of the URL prefix the
client used. Concrete impact: `bitcoin-cli -rpcwallet=alice cmd` sends
to `/wallet/alice` but nimrod routes to whichever wallet
`currentWalletName == ""` resolves to (typically the only loaded
wallet; in multi-wallet mode it raises `RpcMiscError` per
`server.nim:5220`, but the error message **directly references** the
`/wallet/<walletname>` URL contract that the server doesn't honor —
"Use /wallet/<walletname> or specify wallet_name with -rpcwallet
option"). Self-confessing comment / code divergence.

### G20 — `-rpcthreads` (BUG-20, P2-OPS)

Nimrod runs the RPC server on a SINGLE dedicated OS thread
(`rpc_thread.nim`) with `asyncSpawn rpc.processClient(transp)` per
accept (chronos event loop). No worker pool. Core
`httpserver.cpp:438-443`:
```cpp
int rpcThreads = std::max(gArgs.GetArg("-rpcthreads", DEFAULT_HTTP_THREADS), 1);
g_threadpool_http.Start(rpcThreads);
```
Default 16 threads. For nimrod, a slow handler (e.g. `gettxoutsetinfo`,
`scantxoutset`) blocks subsequent reads on the same loop. Operator
UX divergence.

### G21 — Max body-size DoS bound (BUG-21, P1-SEC)

`src/rpc/server.nim:8660-8662`:
```nim
if contentLength > 0:
  let bodyData = await transp.read(contentLength)
```
No upper bound. If a malicious local client (or, under BUG-1, remote)
sends `Content-Length: 1073741824`, nimrod's `transp.read` will
attempt to allocate 1 GiB. Core
`httpserver.cpp:410`:
```cpp
evhttp_set_max_body_size(http, MAX_SIZE);
```
`MAX_SIZE` is `0x02000000` (32 MiB) per `serialize.h`. **P1-SEC**
because the attacker only needs to know the cookie / password OR the
auth gate to be unlocked (which by default it isn't, but the read
sequence is `read headers → check auth → read body`; an attacker who
fails auth never gets to allocate the body), so the practical impact
is post-auth DoS by a privileged but compromised client. Demote to
P1 not P0 because of the auth gate, but still a real bound.

### G22 — Atomic cookie-file write (BUG-22, P0-SEC)

`src/nimrod.nim:1524-1527`:
```nim
let cookiePath = dataDir / ".cookie"
let cookieContent = "__cookie__:" & hexPass
writeFile(cookiePath, cookieContent)
setFilePermissions(cookiePath, {fpUserRead, fpUserWrite})
```

Direct `writeFile`. If the process crashes after `open()` /
`truncate()` but before `write()` completes (or between two write
syscalls if buffering kicks in), the cookie file is left **empty** or
**half-written**. Core
`rpc/request.cpp:113-128`:
```cpp
fs::path filepath_tmp = GetAuthCookieFile(true);   // ".cookie.tmp"
file.open(filepath_tmp.std_path());
file << COOKIEAUTH_USER << ":" << rand_pwd_hex;
file.close();
fs::path filepath = GetAuthCookieFile(false);     // ".cookie"
if (!RenameOver(filepath_tmp, filepath)) { … return ERR; }
```

Tmp-then-`RenameOver` (atomic POSIX rename) guarantees the `.cookie`
seen by any reader is either fully-formed or absent.

**P0-SEC**: An empty `.cookie` would let any `bitcoin-cli` invocation
read `""`, split on `':'`, find no colon, then either error out (good)
or — depending on the cli's tolerance — try to authenticate with an
empty password. A partially-written `.cookie` is worse: if the first
N bytes happen to land on a colon boundary, the cli reads a
truncated cookie and tries it. A concurrent reader during the writeFile
window opens an attack vector via filesystem race that's eliminated
in Core by the atomic rename. Even crash-recovery (nimrod restarted
under systemd) can leave a stale truncated cookie that the new
process never overwrites if the new process crashes too.

Note: also no `setFilePermissions` happens BEFORE write, only after —
so the brief window between `open` and `setFilePermissions` is umask-
dependent (Nim's `writeFile` opens with mode 0o644 default). Core's
`umask 0077` set at process start narrows this. Nimrod has no
explicit umask hardening.

### G23 — `-rpcworkqueue` + 503 backpressure (BUG-23, P2-OPS)

Core `httpserver.cpp:255-258`:
```cpp
if (static_cast<int>(g_threadpool_http.WorkQueueSize()) >= g_max_queue_depth) {
    hreq->WriteReply(HTTP_SERVICE_UNAVAILABLE, "Work queue depth exceeded");
    return;
}
```
Default depth 64. Nimrod has no worker queue → no depth → no 503
fallback. Concurrent RPCs back up on the chronos event loop.

### G24 — `-rpcservertimeout` (BUG-24, P2-OPS)

Core `httpserver.cpp:408`:
```cpp
evhttp_set_timeout(http, gArgs.GetIntArg("-rpcservertimeout", DEFAULT_HTTP_SERVER_TIMEOUT));
```
Default 30s — applied to libevent's HTTP listener. Nimrod's
`processClient` while-loop has no timeout; a client that connects,
sends one header line, and never sends `\r\n\r\n` will hold the
connection (and the chronos task) indefinitely. With BUG-21 absent
and BUG-23 absent, this is a slow-loris DoS surface.

### G25 — `MAX_HEADERS_SIZE` (BUG-25, P2-OPS)

Core `httpserver.cpp:51`:
```cpp
static const size_t MAX_HEADERS_SIZE = 8192;
```
Applied via `evhttp_set_max_headers_size`. Nimrod's
`processClient` reads header lines via `await transp.readLine()` with
no cumulative byte cap. Combined with BUG-24 this is the canonical
slow-loris vector: send N headers each 8 KiB, never reach the empty
line.

### G26 — Hang on Content-Length: 0 / absent (BUG-26, P2-OPS)

`src/rpc/server.nim:8660` only sends a response when `contentLength
> 0`. POST without body (or GET without body, given BUG-2) →
no reply written → server falls through to `inHeaders = true` reset
loop → next `await transp.readLine()` waits for more bytes from a
client that's done sending → blocks until client closes or BUG-24
timeout (which doesn't exist). On a healthy client this manifests as
"`bitcoin-cli` hangs and times out" rather than receiving a clean
`HTTP/1.1 400 Bad Request`.

### G27 — Keep-alive reset is dead code (BUG-27, P3)

`src/rpc/server.nim:8687-8691`:
```nim
# Reset for next request (keep-alive)
inHeaders = true
headers.clear()
contentLength = 0
authHeader = ""
```
Unreachable: line 8685 `break`s out of the while loop after the
response is written. The only path that reaches the reset is the
`contentLength == 0` branch (BUG-26), which is broken for the
unrelated reason. Net effect: nimrod is HTTP/1.0-style
single-request-per-connection. Cosmetic but the comment misrepresents
the contract.

### G28 — Header key starting with "GET"/"POST" (BUG-28, P3)

`src/rpc/server.nim:8693-8702`: the request-line `elif` branch
matches `startsWith("POST")` / `startsWith("GET")` BEFORE the
colon-containing branch. A legitimate header like `Get-User-Time:`
or `Post-Authorization:` is collapsed to "request line ignore" and
silently dropped. Cosmetic for the standard contract (no such RFC-
defined header), but documents the parser's prefix-matching weakness.

### G29 — CSPRNG for cookie (PRESENT)

`src/nimrod.nim:1517` reads 32 bytes via
`std/sysrand urandom`, matching Core `request.cpp:106`
(`GetRandBytes`). Width and entropy parity confirmed.

### G30 — Auth bypass guard (PRESENT)

`src/rpc/server.nim:8602-8603`:
```nim
if not hasUserPass and not hasCookie:
  return true  # No auth configured — open access
```
In default startup (`nimrod.nim:2253`) the cookie is unconditionally
generated, so `hasCookie` is true and the open-access branch is
unreachable. PRESENT defensively, but the open-access fallback would
be P0-SEC if any future refactor moved cookie generation behind a
conditional. The audit pins this contract so a regression is caught.

---

## Summary

  - **30 gates total**.
  - **PRESENT**: G1 (`__cookie__` constant), G29 (CSPRNG width),
    G30 (open-access fallback unreachable in default startup).
  - **BUGS** (28 across 28 gates; G8 carries two BUG-IDs because
    `-rpcbind` + `-rpcallowip` are two halves of the same ACL):
      - **P0-SEC ×3**: BUG-2 (GET-as-POST), BUG-5
        (timing-attackable string equality), BUG-22 (non-atomic cookie
        write).
      - **P1-SEC ×6**: BUG-1 / BUG-8 (`-rpcbind`/`-rpcallowip`),
        BUG-3 (no IPv6 bind), BUG-4 (no `-rpcauth`), BUG-6 (no
        brute-force throttle), BUG-7 (no `-rpcwhitelist`), BUG-21 (no
        max-body bound).
      - **P1-OPS ×2**: BUG-9 (`-rpccookieperms`), BUG-10
        (`-rpccookiefile`).
      - **P1-CORRECTNESS ×9**: BUG-11 (HTTP status), BUG-12
        (reply shape vs version), BUG-13 (notification semantics),
        BUG-14 (`jsonrpc` field validation), BUG-15 (`params` type
        validation), BUG-16 (all-notification 204), BUG-17 (empty
        batch reply), BUG-18 (batch element non-object), BUG-19
        (`/wallet/<name>` URL routing).
      - **P2-OPS ×5**: BUG-20 (`-rpcthreads`), BUG-23
        (`-rpcworkqueue` + 503), BUG-24 (`-rpcservertimeout`),
        BUG-25 (`MAX_HEADERS_SIZE`), BUG-26 (hang on Content-Length 0).
      - **P3 ×2**: BUG-27 (keep-alive dead code), BUG-28
        (header-key prefix shadowing).

## Notes for follow-on fix waves

**Recommended ordering** (smallest blast radius first; security first):

  1. BUG-22 (atomic cookie write) — single-file 5-line change in
     `nimrod.nim:1524-1527`; uses Nim stdlib `moveFile` on
     `.cookie.tmp` → `.cookie`. Sets `setFilePermissions` BEFORE
     `moveFile` so the visible cookie always has 0600.
  2. BUG-5 (constant-time equality) — small helper in
     `crypto/hashing.nim` (constant-time compare; the project already
     uses `nimcrypto`).  Apply to both branches in `checkAuth`.
  3. BUG-2 (POST-only gate) — distinguish request line from header
     line by requiring the second whitespace-separated token to start
     with `/` and the third to be `HTTP/…`. Reject anything that
     isn't `POST` with a `HTTP/1.1 405 Method Not Allowed` (plus
     `Allow: POST`).
  4. BUG-19 (`/wallet/<name>` extraction) — parse the URL from the
     request line (currently `discard`ed at `server.nim:8693-8695`)
     and set `rpc.currentWalletName` per-request. Needs careful
     thread-safety thinking because `rpc` is shared across
     `asyncSpawn`ed `processClient` tasks; per-request context object
     is the clean fix.
  5. BUG-21 + BUG-24 + BUG-25 + BUG-6 (DoS bounds + throttle) —
     three small literal caps + a `chronos.sleepAsync(250 * msec)` on
     auth-fail. Add as defaults; constants from Core.
  6. BUG-11 + BUG-12 + BUG-13 + BUG-14 + BUG-15 (JSON-RPC version /
     shape parity) — single refactor of `handleSingleRequest` to
     parse `jsonrpc` field first, branch on version, then validate
     `params` type. Reuse Core's V1/V2 reply shape.
  7. BUG-16 + BUG-17 + BUG-18 (batch reply parity) — small additions
     to `handleRequest` batch path.
  8. BUG-1 + BUG-3 + BUG-7 + BUG-8 + BUG-9 + BUG-10 + BUG-20 +
     BUG-23 (CLI flags + ACL + worker pool + bind list) — needs
     argparse plumbing in `nimrod.nim`; can be staged by flag.
  9. BUG-4 (`-rpcauth` HMAC) — bigger lift; needs HMAC-SHA256 import
     and a stable parser for `<user>:<salt>$<hex_hmac>`. Defer until
     #2 lands (constant-time compare is the reusable primitive).
 10. BUG-26 (POST Content-Length 0) and BUG-27 / BUG-28 (cosmetic
     parser fixes) — bundle with #3.

**Caveat**: BUG-2 + BUG-21 + BUG-24 + BUG-25 collectively interact —
fixing one without the others moves the DoS surface around. Land them
in a single follow-up wave to avoid the well-known "fix moves
the trap" anti-pattern.
