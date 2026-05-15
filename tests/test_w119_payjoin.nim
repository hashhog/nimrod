## W119 BIP-78 PayJoin fleet audit — nimrod (Nim)
##
## Verdict: MISSING ENTIRELY.
##
## Bitcoin Core has no PayJoin implementation; the wallet-side P2EP /
## "PayJoin v1" feature lives outside Core (BIP-78 spec + payjoin.org +
## btcpayserver/payjoin Rust reference + BIP21 `pj=`/`pjos=` extensions).
## A grep of the nimrod tree for `payjoin`, `BIP78`, `pj=`, `pjos`,
## `additionalfeeoutputindex`, `maxadditionalfeecontribution`,
## `disableoutputsubstitution`, and `minfeerate` returns zero hits.
##
## 30-gate scope (BIP-78 + BIP-21 `pj=`):
##   Receiver HTTP        G1  receiver POST endpoint accepts Original PSBT
##   Sender HTTP          G2  sender posts Original PSBT to pj= URL
##   TLS / Tor            G3  TLS to clearnet endpoint or Tor onion fallback
##   Original PSBT        G4  Original PSBT deserialize + sanity (incl. signed)
##   Receiver validate    G5  receiver validates sender's Original PSBT
##   Fee output id        G6  receiver identifies sender's fee-bearing output
##   Receiver add inputs  G7  receiver injects own inputs (P2EP join)
##   Receiver modify out  G8  receiver may resize sender-flagged fee output
##   Receiver fee adjust  G9  receiver bumps fee under sender-supplied bounds
##   Sender anti-snoop A  G10 sender enforces output-rule invariants on payjoin
##   Sender anti-snoop B  G11 sender enforces scriptSig type match for new inputs
##   Sender anti-snoop C  G12 sender enforces "no new sender inputs"
##   Sender anti-snoop D  G13 sender enforces max fee contribution
##   Sender anti-snoop E  G14 sender honors `disableoutputsubstitution=1`
##   Sender anti-snoop F  G15 sender enforces `minfeerate`
##   Query params         G16 v=1 / additionalfeeoutputindex /
##                            maxadditionalfeecontribution / disableoutput-
##                            substitution / minfeerate are parsed
##   Errors               G17 four BIP-78 error kinds (unavailable /
##                            not-enough-money / version-unsupported /
##                            original-psbt-rejected) are produced
##   Receiver TTL         G18 receiver request TTL enforced (60s default)
##   Receiver no-double   G19 receiver refuses replays of same Original PSBT
##   Anti-fingerprint     G20 receiver UTXO selection avoids deterministic leak
##   v=1 header           G21 sender + receiver advertise BIP-78 version 1
##   Sender fallback      G22 sender broadcasts Original PSBT on receiver fail
##   Content-Type         G23 receiver requires text/plain (base64) per spec
##   HTTPS cert pinning   G24 sender enforces TLS cert chain on clearnet pj=
##   Tor onion endpoint   G25 sender supports .onion pj= via local SOCKS5
##   RPC getpayjoin       G26 `getpayjoinrequest` RPC exposes a receive URI
##   RPC sendpayjoin      G27 `sendpayjoinrequest` RPC posts to a pj= URL
##   BIP-21 pj=           G28 BIP-21 URI parser recognizes `pj=` param
##   BIP-21 pjos=         G29 BIP-21 URI parser recognizes `pjos=` (output sub)
##   Replay protection    G30 receiver invalidates Original PSBT after success
##
## BUGs found (this audit):
##   BUG-1 (HIGH)   G1-G2,G16,G17,G18,G19,G20,G21,G23,G30
##                  PayJoin receiver subsystem MISSING ENTIRELY.
##                  No HTTP POST handler exists at any path. `rest.nim`'s
##                  `processRestClient` only branches on lines starting
##                  with `"GET "` — POST is silently dropped (the client
##                  connection idles until close). Even if a POST were
##                  routed, no Original-PSBT validator, no fee-output
##                  identifier, no input-injection helper, and no
##                  replay store exist. This is the textbook
##                  "feature absent" shape — not dead-helper, not
##                  two-pipeline, just absent.
##
##   BUG-2 (HIGH)   G2,G10-G15,G22,G24,G25,G27
##                  PayJoin sender subsystem MISSING ENTIRELY.
##                  No HTTP client (chronos `httpclient`/`httputils`
##                  modules are not imported anywhere in the tree —
##                  `grep -r "import .*http" src/` returns zero hits).
##                  None of the sender anti-snoop invariants
##                  (BIP-78 §"Receiver's original PSBT" rules and
##                  §"Checking the Proposal") are implemented;
##                  consequently a malicious receiver could
##                  add unbounded new inputs, swap outputs, or
##                  inflate the fee with no client-side rejection.
##                  No `sendpayjoinrequest` RPC, no fallback path.
##                  Sender-side absence is more severe than receiver-
##                  side absence because nimrod nodes acting as
##                  payers would be defenseless if a sender subsystem
##                  were retrofitted naively.
##
##   BUG-3 (HIGH)   G3,G24,G25
##                  No TLS / no .onion HTTPS client available.
##                  The chronos build does not pull `chronos/apps/http`
##                  or any TLS layer; the in-tree `RestServer` formats
##                  raw HTTP/1.1 over plaintext StreamTransport at
##                  127.0.0.1 only (`rest.nim:1024`). PayJoin's BIP-78
##                  endpoint MUST be either HTTPS-with-valid-cert or
##                  a Tor onion (BIP-78 §"Discovery" / §"Communicating
##                  with the receiver"). Without TLS support, even a
##                  minimal sender retrofit would leak the Original
##                  PSBT in clear over the loopback or the public net.
##
##   BUG-4 (MED)    G28,G29
##                  No BIP-21 URI parser.
##                  Grep for `bitcoin:` (URI scheme), `parseURI`,
##                  `parseBitcoinURI`, or any `Uri` import-of-use shows
##                  only doc-comment hits ("the most performance-critical
##                  hash operation in Bitcoin:") — no actual parser.
##                  PayJoin endpoint discovery in BIP-21 requires
##                  recognising `pj=<endpoint>` and `pjos=0|1` extension
##                  query parameters; nimrod's wallet `sendtoaddress`
##                  / GUI surfaces accept bare addresses only.
##
##   BUG-5 (MED)    G18,G19,G30
##                  No replay / TTL infrastructure.
##                  Even if BUG-1 were closed by adding a POST handler,
##                  there is no per-Original-PSBT TTL table, no replay
##                  set, and no per-receiver rate-limit. BIP-78 §"Reuse
##                  protection" requires the receiver to invalidate the
##                  Original PSBT after a successful proposal, and to
##                  refuse a second proposal for the same Original PSBT
##                  within a window. This entire bookkeeping layer is
##                  absent.
##
##   BUG-6 (LOW)    G20
##                  No UTXO selection anti-fingerprinting policy.
##                  `wallet/coinselection.nim` exposes BnB + Knapsack
##                  (W118 G29-G30 covered) but no PayJoin-specific
##                  policy ("avoid using a UTXO that uniquely identifies
##                  the receiver across sessions"). Closing BUG-1 alone
##                  would expose this gap — a naïve receiver would leak
##                  by picking the largest available UTXO every time.
##
## Cross-cutting with FIX-61 (W118 bumpfee/psbtbumpfee):
##   FIX-61 added `wallet/feebumper.nim` exporting
##   `createRateBumpTransaction` + `BumpFeeRequest`/`BumpFeeOutcome`/
##   `BumpFeeError`. A future PayJoin receiver fix could reuse this
##   helper for G9 (receiver fee adjustment under sender bounds) once
##   the bounds-aware adapter is added — `feebumper.nim` already
##   centralises the "rate to absolute-fee delta" math against the
##   live mempool's `minFeeRate` and `incrementalRelayFeeSatVb`. PSBT
##   helpers (`createPsbt`, `combinePsbts`, `finalizePsbt`,
##   `extractTransaction`, `serialize`/`deserialize`, `toBase64`/
##   `fromBase64`) are already present in `wallet/psbt.nim` and can
##   serve G4 / G8 / G22.
##
## Surprises:
##   - REST server uses a GET-only hand-rolled HTTP parser, not the
##     standard `chronos/apps/http` server (which exists but is not
##     pulled in). Adding POST is a non-trivial parser extension.
##   - The chronos async stack is already wired throughout (network,
##     RPC, storage), so the runtime substrate for an async PayJoin
##     receiver loop is in place — only the HTTP layer + spec logic
##     are missing.
##   - PSBT round-trip + finalize + extract are fully implemented and
##     test-covered in `test_psbt.nim` / `test_bip174.nim` (G15-G16 in
##     W118). A PayJoin retrofit would not need PSBT plumbing.

import std/[unittest, options, strutils]
import ../src/wallet/psbt
import ../src/wallet/feebumper
import ../src/wallet/wallet
import ../src/wallet/bip21
import ../src/rpc/rest
import ../src/mempool/mempool

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# A trivial Original-PSBT-shaped blob exercise: an unsigned PSBT containing
# a single input + single output. We use the existing wallet helpers so this
# test will start passing automatically the day a PayJoin module appears
# (just by `compiles()` flipping).

# ---------------------------------------------------------------------------
# G1-G2  HTTP transport (BIP-78 §Communicating with the receiver)
# ---------------------------------------------------------------------------
suite "W119 G1-G2 PayJoin HTTP transport":

  test "G1 BUG-1 (HIGH) — no receiver POST handler exists":
    ## BIP-78 receiver MUST accept POST /<endpoint> with Content-Type
    ## text/plain and a base64-encoded PSBT body. nimrod's REST server
    ## `processRestClient` only branches on `"GET "` (rest.nim:1009).
    ## A POST line falls through the `# Skip other headers` comment
    ## and the connection idles. No symbol named `handlePayJoinPost`
    ## or `handlePayJoinReceive` exists.
    check not compiles(handlePayJoinPost)
    check not compiles(handlePayJoinReceive)
    check not compiles(payjoinReceive)
    check not compiles(processPayJoinRequest)

  test "G2 BUG-2 (HIGH) — no sender HTTP client":
    ## BIP-78 sender MUST POST the Original PSBT to the URL in `pj=`.
    ## No HTTP client module is imported anywhere in src/. The chronos
    ## async stack is wired, but `chronos/apps/http/httpclient` is
    ## absent from the dependency closure. No `sendPayJoinRequest`
    ## helper, no `postOriginalPsbt`.
    check not compiles(sendPayJoinRequest)
    check not compiles(postOriginalPsbt)
    check not compiles(payjoinSenderPost)

  test "G1 surface check: REST router has no payjoin route":
    ## `handleRestRequest` (rest.nim:925) hard-codes the route table
    ## (block/, headers/, tx/, getutxos/, mempool/info.json,
    ## blockfilter/, blockfilterheaders/). No `payjoin` token appears.
    ## `handleRestRequest` is exported (`*`), so `compiles()` can
    ## reference it directly. The router falls through to Http404 for
    ## anything not in its hard-coded prefix list — including any
    ## `payjoin` path — without ever inspecting the request method.
    check compiles(handleRestRequest)
    check not compiles(handleRestPayJoin)
    check not compiles(handleRestPayJoinPost)

# ---------------------------------------------------------------------------
# G3  TLS / Tor onion (BIP-78 §Communicating with the receiver)
# ---------------------------------------------------------------------------
suite "W119 G3 PayJoin TLS / Tor":

  test "G3 BUG-3 (HIGH) — no TLS client available":
    ## BIP-78 endpoints must be HTTPS (valid cert) or .onion.
    ## nimrod's chronos build does not pull a TLS layer; `rest.nim`
    ## opens a raw `StreamTransport` and hand-formats HTTP/1.1
    ## strings. No `TlsStream`, no `chronos/apps/http` import.
    check not compiles(TlsStream)
    check not compiles(newAsyncSslContext)
    check not compiles(httpsClient)

  test "G3 RestServer has no TLS state":
    ## Pinned for regression: any future TLS retrofit must add fields
    ## or otherwise flip these checks. The receiver endpoint cannot be
    ## exposed publicly under the current build without breaking
    ## BIP-78 §Discovery — `rest.nim:1024` opens a plaintext
    ## `createStreamServer` on 127.0.0.1 with `flags = {ReuseAddr}`
    ## and never wraps it in TLS.
    ## `RestServer` is a ref-object exported as `RestServer*`; if a
    ## TLS retrofit landed it would add a `tlsEnabled`/`sslContext`
    ## field and `compiles(RestServer().tlsEnabled)` would flip true.
    check compiles(RestServer)
    check not compiles(RestServer().tlsEnabled)
    check not compiles(RestServer().sslContext)

# ---------------------------------------------------------------------------
# G4  Original PSBT deserialize + sanity (incl. fully-signed sender input)
# ---------------------------------------------------------------------------
suite "W119 G4 Original PSBT deserialize":

  test "G4 PSBT plumbing exists (precondition for any receiver)":
    ## Pinned: a PayJoin retrofit would NOT need to add PSBT codecs;
    ## `wallet/psbt.nim` already supplies them (covered by W118 G13-G16,
    ## test_psbt.nim, test_bip174.nim). This test guards the precondition.
    check compiles(serialize(Psbt()))
    check compiles(deserialize(@[]))
    check compiles(toBase64(Psbt()))
    check compiles(fromBase64(""))

  test "G4 BUG-1 — no PayJoin-aware Original-PSBT validator":
    ## BIP-78 receiver MUST reject Original PSBTs that are not finalized
    ## on all sender inputs (sender-signed precondition). No symbol
    ## `validateOriginalPsbt` / `isFinalizedSenderInputs` / similar.
    check not compiles(validateOriginalPsbt)
    check not compiles(isFullySignedOriginal)
    check not compiles(checkOriginalPsbtForPayJoin)

# ---------------------------------------------------------------------------
# G5  Receiver-side Original-PSBT validation
# ---------------------------------------------------------------------------
suite "W119 G5 Receiver validation":

  test "G5 BUG-1 — no receiver validation pipeline":
    ## Receiver MUST check: at least one input signed, no malleable
    ## tx flags, no high-fee tx, valid fee rate vs declared
    ## minfeerate, no PSBT-v2 elements (unsupported), version matches.
    check not compiles(receiverValidateOriginal)
    check not compiles(checkOriginalFeeRate)
    check not compiles(rejectMalleableOriginal)

# ---------------------------------------------------------------------------
# G6  Fee output identification (additionalfeeoutputindex)
# ---------------------------------------------------------------------------
suite "W119 G6 Fee output identification":

  test "G6 BUG-1 — no fee-output index parser":
    ## BIP-78 query param `additionalfeeoutputindex=N` tells the receiver
    ## which output may shrink to absorb the receiver's added fee.
    ## No parser, no validator.
    check not compiles(parseAdditionalFeeOutputIndex)
    check not compiles(additionalFeeOutputIndex)
    check not compiles(getPayJoinFeeOutputIndex)

# ---------------------------------------------------------------------------
# G7  Receiver injects own inputs
# ---------------------------------------------------------------------------
suite "W119 G7 Receiver input injection":

  test "G7 BUG-1 — no receiver input-injection helper":
    ## Receiver MUST add ≥1 input from its own wallet (the whole point
    ## of P2EP). No symbol exists.
    check not compiles(receiverAddInputs)
    check not compiles(payjoinJoinInputs)
    check not compiles(injectReceiverInputs)

# ---------------------------------------------------------------------------
# G8  Receiver may resize sender's fee output
# ---------------------------------------------------------------------------
suite "W119 G8 Receiver output modification":

  test "G8 BUG-1 — no receiver output-modification path":
    ## Receiver may decrement the value of the sender-flagged fee
    ## output to absorb the added fee for its new inputs, IF
    ## `pjos=0`/`disableoutputsubstitution=0`. No helper exists.
    check not compiles(modifyOriginalOutput)
    check not compiles(receiverAdjustFeeOutput)

# ---------------------------------------------------------------------------
# G9  Receiver fee adjustment (bounded by sender's maxadditionalfeecontribution)
# ---------------------------------------------------------------------------
suite "W119 G9 Receiver fee adjustment":

  test "G9 BUG-1 — no receiver fee-adjustment routine":
    ## Receiver computes added-input weight, derives fee delta at the
    ## negotiated rate, then bumps the fee — but ONLY up to
    ## `maxadditionalfeecontribution`. No helper exists.
    check not compiles(receiverComputeAddedFee)
    check not compiles(applyReceiverFeeDelta)

  test "G9 precondition — feebumper.nim is reusable for G9 retrofit":
    ## Pinned: FIX-61 W118 added `wallet/feebumper.nim`. A PayJoin
    ## retrofit can reuse its rate→absolute-fee math against live
    ## mempool minRelayFee / incremental relay fee. This guards the
    ## reuse target so a refactor does not silently break it.
    check compiles(createRateBumpTransaction)
    check compiles(BumpFeeRequest)
    check compiles(BumpFeeOutcome)
    check compiles(BumpFeeError)

# ---------------------------------------------------------------------------
# G10-G15  Sender anti-snoop invariants (BIP-78 §Checking the Proposal)
# ---------------------------------------------------------------------------
suite "W119 G10-G15 Sender anti-snoop invariants":

  test "G10 BUG-2 — no sender output-rule enforcement":
    ## BIP-78 §Checking the Proposal "the original outputs must be
    ## present in the proposal, except possibly the fee output if
    ## not disabled". No symbol checks this.
    check not compiles(senderCheckOriginalOutputsPresent)
    check not compiles(checkPayJoinOutputRules)

  test "G11 BUG-2 — no sender scriptSig type-match check":
    ## BIP-78 §Checking the Proposal "the inputs the receiver added
    ## must be of the same input type as the original inputs"
    ## (anti-clustering: a P2WPKH wallet joining a P2WSH proposal
    ## would leak heuristically). No symbol checks this.
    check not compiles(senderCheckInputTypeMatch)
    check not compiles(checkPayJoinInputTypes)

  test "G12 BUG-2 — no sender 'no new sender inputs' check":
    ## BIP-78 §Checking the Proposal "the receiver may only add new
    ## inputs, never new outputs belonging to the sender". A
    ## malicious receiver could try to insert dust attaching to the
    ## sender. No symbol checks this.
    check not compiles(senderCheckNoNewSenderInputs)
    check not compiles(senderEnforceInputSetIntersection)

  test "G13 BUG-2 — no sender max-fee enforcement":
    ## BIP-78 sender MUST refuse a proposal whose absolute fee
    ## increase exceeds `maxadditionalfeecontribution`. No symbol.
    check not compiles(senderEnforceMaxFee)
    check not compiles(checkAdditionalFeeBound)

  test "G14 BUG-2 — no sender disableoutputsubstitution honoring":
    ## BIP-21 `pjos=1` (or BIP-78 query `disableoutputsubstitution=1`)
    ## means the sender refuses any change to its outputs. No symbol.
    check not compiles(senderDisableOutputSubstitution)
    check not compiles(checkOutputSubstitutionDisabled)

  test "G15 BUG-2 — no sender minfeerate enforcement":
    ## Sender supplies `minfeerate` and MUST refuse a proposal whose
    ## resulting fee rate falls below it. No symbol.
    check not compiles(senderEnforceMinFeeRate)
    check not compiles(checkPayJoinMinFeeRate)

# ---------------------------------------------------------------------------
# G16  BIP-78 query parameters
# ---------------------------------------------------------------------------
suite "W119 G16 Query parameter parsing":

  test "G16 BUG-1 — no BIP-78 query parameter parser":
    ## Five canonical params: v / additionalfeeoutputindex /
    ## maxadditionalfeecontribution / disableoutputsubstitution /
    ## minfeerate. None parsed anywhere.
    check not compiles(parsePayJoinQueryParams)
    check not compiles(PayJoinReceiveOptions)
    check not compiles(parsePayJoinReceiverQuery)

# ---------------------------------------------------------------------------
# G17  Four BIP-78 error codes
# ---------------------------------------------------------------------------
suite "W119 G17 Error codes":

  test "G17 BUG-1 — no BIP-78 error enum":
    ## `unavailable` / `not-enough-money` / `version-unsupported` /
    ## `original-psbt-rejected` are the four canonical strings.
    ## No symbol, no enum.
    check not compiles(PayJoinError)
    check not compiles(PayJoinErrorKind)
    check not compiles(pjeUnavailable)
    check not compiles(pjeNotEnoughMoney)
    check not compiles(pjeVersionUnsupported)
    check not compiles(pjeOriginalPsbtRejected)

# ---------------------------------------------------------------------------
# G18  Receiver request TTL
# ---------------------------------------------------------------------------
suite "W119 G18 Receiver TTL":

  test "G18 BUG-5 — no receiver TTL infrastructure":
    ## BIP-78 receivers SHOULD time out a stale Original PSBT after
    ## ~60s. No TTL table, no `payjoinReceiveTtlSeconds` constant.
    check not compiles(PayJoinReceiveTtlSeconds)
    check not compiles(payjoinSessionTable)
    check not compiles(expirePayJoinSessions)

# ---------------------------------------------------------------------------
# G19  Receiver no-double-spend protection on Original PSBT
# ---------------------------------------------------------------------------
suite "W119 G19 Receiver replay protection":

  test "G19 BUG-5 — no replay-prevention table":
    ## BIP-78 §Reuse protection: a receiver MUST refuse a second
    ## proposal for the same Original PSBT (else attacker can probe
    ## receiver UTXO set). No replay set.
    check not compiles(payjoinSeenOriginals)
    check not compiles(payjoinReplaySet)
    check not compiles(checkPayJoinReplay)

# ---------------------------------------------------------------------------
# G20  Anti-fingerprint UTXO selection
# ---------------------------------------------------------------------------
suite "W119 G20 Anti-fingerprint UTXO selection":

  test "G20 BUG-6 — no PayJoin-specific UTXO selection policy":
    ## Receiver's UTXO pick reveals identity if it always selects
    ## the largest / most-recent. BIP-78 §Discovery hints at the
    ## need for a randomised policy. No symbol.
    check not compiles(selectPayJoinReceiverUtxo)
    check not compiles(payjoinAvoidFingerprint)

# ---------------------------------------------------------------------------
# G21  v=1 advertised on the wire
# ---------------------------------------------------------------------------
suite "W119 G21 Version advertisement":

  test "G21 BUG-1 — no version constant":
    ## BIP-78 §"BIP-78 endpoint" mandates `v=1` on the request URL
    ## and matching advertisement from the receiver. No version const.
    check not compiles(PAYJOIN_VERSION)
    check not compiles(PayJoinSupportedVersion)

# ---------------------------------------------------------------------------
# G22  Sender fallback path on receiver failure
# ---------------------------------------------------------------------------
suite "W119 G22 Sender fallback":

  test "G22 BUG-2 — no sender fallback to broadcast Original":
    ## BIP-78 sender MUST broadcast the Original PSBT (already
    ## valid + signed) if the receiver fails / times out — the
    ## transaction completes as a normal payment. No symbol does
    ## this orchestration.
    check not compiles(payjoinSenderFallback)
    check not compiles(broadcastOriginalOnPayJoinFailure)

# ---------------------------------------------------------------------------
# G23  Content-Type validation on receiver
# ---------------------------------------------------------------------------
suite "W119 G23 Content-Type":

  test "G23 BUG-1 — no Content-Type validation":
    ## Receiver MUST accept only Content-Type: text/plain (body is
    ## base64-PSBT). Since there is no POST handler at all, there is
    ## no Content-Type check.
    check not compiles(checkPayJoinContentType)
    check not compiles(payjoinRequireTextPlain)

# ---------------------------------------------------------------------------
# G24-G25  HTTPS / Tor onion endpoints
# ---------------------------------------------------------------------------
suite "W119 G24-G25 HTTPS / Tor onion":

  test "G24 BUG-3 — no TLS cert chain validator":
    ## BIP-78 §Communicating "if the URL is HTTPS, the sender MUST
    ## verify the server certificate". No verifier.
    check not compiles(verifyPayJoinTlsCert)
    check not compiles(payjoinHttpsVerify)

  test "G25 BUG-3 — no .onion endpoint client":
    ## BIP-78 §Discovery permits .onion endpoints (via SOCKS5).
    ## nimrod has proxy.nim (FIX-56 W117) but no PayJoin caller
    ## that wires through it.
    check not compiles(payjoinOnionClient)
    check not compiles(payjoinSocks5Send)

# ---------------------------------------------------------------------------
# G26-G27  RPC surface
# ---------------------------------------------------------------------------
suite "W119 G26-G27 RPC surface":

  test "G26 BUG-1 — no getpayjoinrequest RPC handler":
    ## Receivers expose `getpayjoinrequest` to mint a fresh receive URI
    ## including `pj=` + `pjos=`. nimrod's RPC dispatch table
    ## (`handleRpcMethod`, server.nim:7900+) has no such case.
    check not compiles(handleGetPayJoinRequest)
    check not compiles(handleNewPayJoinRequest)

  test "G27 BUG-2 — no sendpayjoinrequest RPC handler":
    ## Senders use `sendpayjoinrequest <bip21-uri> <amount>` to
    ## start a PayJoin flow. No handler.
    check not compiles(handleSendPayJoinRequest)
    check not compiles(handleStartPayJoin)

# ---------------------------------------------------------------------------
# G28-G29  BIP-21 URI extension parameters
# ---------------------------------------------------------------------------
suite "W119 G28-G29 BIP-21 pj= / pjos= parser":

  test "G28 BUG-4 (CLOSED by FIX-62) — pj= parsed":
    ## BIP-21 `pj=<URL>` extension param now parsed via
    ## `src/wallet/bip21.nim` (FIX-62). The earlier `check not compiles`
    ## assertions are invalidated and the symbols are exercised live.
    let u = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" &
      "?pj=https%3A%2F%2Fexample.com%2Fpj")
    check u.isSome
    check u.get.pj.isSome
    check u.get.pj.get == "https://example.com/pj"
    let pj = parseBip21PayJoinParam(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" &
      "?pj=https%3A%2F%2Fexample.com%2Fpj")
    check pj.isSome and pj.get == "https://example.com/pj"

  test "G29 BUG-4 (CLOSED by FIX-62) — pjos= parsed":
    ## BIP-21 `pjos=0|1` extension toggles
    ## `disableoutputsubstitution`. Now parsed via FIX-62. The earlier
    ## `check not compiles` assertions are invalidated.
    let u1 = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?pjos=1")
    let u0 = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?pjos=0")
    check u1.isSome and u1.get.pjos.get == true
    check u0.isSome and u0.get.pjos.get == false
    check payjoinOutputSubstitutionFlag(u1.get) == true
    check payjoinOutputSubstitutionFlag(u0.get) == false
    let helper = parseBip21OutputSubstitution(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?pjos=1")
    check helper.isSome and helper.get == true

# ---------------------------------------------------------------------------
# G30  Replay protection on success path
# ---------------------------------------------------------------------------
suite "W119 G30 Replay protection on success":

  test "G30 BUG-5 — no post-success invalidation":
    ## After a successful PayJoin proposal, the receiver MUST mark
    ## the Original PSBT as consumed so a replay (with same inputs)
    ## fails with `unavailable`. No such bookkeeping.
    check not compiles(consumePayJoinSession)
    check not compiles(payjoinFinalizeSession)
    check not compiles(invalidateOriginalAfterSuccess)

# ---------------------------------------------------------------------------
# Sanity: confirm we're not silently passing because of typos
# ---------------------------------------------------------------------------
suite "W119 sanity: existing FIX-61 / PSBT symbols remain present":

  test "FIX-61 surface (W118 G22) intact":
    check compiles(createRateBumpTransaction)
    check compiles(BumpFeeRequest)
    check compiles(BumpFeeError)

  test "PSBT surface (W118 G13-G16) intact":
    check compiles(serialize(Psbt()))
    check compiles(deserialize(@[]))
    check compiles(toBase64(Psbt()))
    check compiles(fromBase64(""))

  test "Mempool RBF surface (W118 G19-G20) intact":
    check compiles(signalsOptInRBF(Transaction()))
    check MaxBip125RbfSequence == 0xfffffffd'u32
