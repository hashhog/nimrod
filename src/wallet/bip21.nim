## BIP-21 — Bitcoin URI scheme parser
##
## Reference: https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki
##
## Grammar (BIP-21 §"Specification"):
##
##   bitcoinurn     = "bitcoin:" bitcoinaddress [ "?" bitcoinparams ]
##   bitcoinparams  = bitcoinparam [ "&" bitcoinparams ]
##   bitcoinparam   = [ amountparam | labelparam | messageparam |
##                      otherparam | reqparam ]
##   reqparam       = "req-" pname "=" pvalue
##
## Semantics:
##   * Param keys are case-insensitive (per BIP-21 grammar `pname` is opaque,
##     but real-world clients — including BIP-78 / payjoin.org reference —
##     normalise to lower-case on both sides). We compare keys lower-cased.
##   * Param values are percent-decoded (RFC 3986 §2.1).
##   * Any param starting with `req-` whose name (after the `req-` prefix) is
##     unknown MUST cause the URI to be rejected (BIP-21 §"Forward
##     compatibility").
##   * Any other unknown param is silently ignored.
##   * Unprefixed strings (no `bitcoin:` scheme) are rejected.
##
## Recognised params (this implementation):
##   amount    — BIP-21 amount in BTC, decimal float
##   label     — BIP-21 label
##   message   — BIP-21 message
##   lightning — BOLT-11 invoice (BIP-21 §"URI examples", BOLT-11 §"URI")
##   pj        — BIP-78 PayJoin endpoint URL
##   pjos      — BIP-78 `disableoutputsubstitution` toggle (0|1)
##
## The `req-` prefix is treated specially: any `req-<X>=<v>` where `<X>`
## is not a recognised param (after stripping `req-`) is a hard reject.
##
## This module is consumed by the (future) PayJoin sender RPC
## `sendpayjoinrequest` (W119 BUG-2 / G27), the `getpayjoinrequest` URI
## emitter (W119 BUG-1 / G26), and any wallet UI that accepts a BIP-21
## URI in place of a bare address. The W119 audit (`tests/test_w119_payjoin.nim`)
## flagged the absence of this module as BUG-4 / G28-G29.
##
## NOTE: This module deliberately does NOT depend on the address codec —
## a parsed `Bip21Uri` carries the address as a raw string, and the
## caller is expected to feed it to `crypto/address.decodeAddress` (which
## already validates network-appropriate prefix / HRP). Keeping the parser
## codec-agnostic lets it be reused for testnet / regtest / signet without
## injecting a `Network` dependency.

import std/[options, strutils, tables, parseutils]

type
  Bip21Error* = enum
    ## Soft enum; callers convert to RPC errors or wallet UI messages.
    beNoScheme           ## input does not start with `bitcoin:`
    beBadPercentEncoding ## malformed `%XX` escape
    beUnknownReqParam    ## `req-<X>=` for unrecognised `<X>`
    beBadAmount          ## `amount=` is not a decimal float
    beBadPjosFlag        ## `pjos=` is not `0` or `1`
    beDuplicateParam     ## same param key supplied twice (RFC 3986
                         ## ambiguous; BIP-21 silent — we reject to
                         ## match the reference Rust `payjoin` crate
                         ## and avoid silent last-wins surprises)

  Bip21Uri* = object
    ## Parsed result of a BIP-21 `bitcoin:<addr>?<query>` URI.
    ##
    ## Fields are `Option[T]` because every query param is optional
    ## (BIP-21 grammar allows the URI to be `bitcoin:<addr>` alone).
    address*: string              ## raw address string; caller validates
    amount*: Option[float64]      ## BTC, decimal
    label*: Option[string]        ## percent-decoded label
    message*: Option[string]      ## percent-decoded message
    lightning*: Option[string]    ## BOLT-11 invoice (raw)
    pj*: Option[string]           ## BIP-78 endpoint URL (raw)
    pjos*: Option[bool]           ## BIP-78 `disableoutputsubstitution`
                                  ## (`pjos=1` → true → substitution
                                  ## disabled; `pjos=0` → false → allowed)
    ## Note on req-: unrecognised `req-X` causes a parse error rather than
    ## being stored. Recognised `req-<known>=` is treated as the same as
    ## `<known>=` (per BIP-21 "the receiver MUST process it normally").

# ---------------------------------------------------------------------------
# Percent decoding (RFC 3986 §2.1)
# ---------------------------------------------------------------------------

proc hexNibble(c: char): int {.inline.} =
  ## Returns 0..15 for a hex digit, -1 otherwise.
  case c
  of '0'..'9': ord(c) - ord('0')
  of 'a'..'f': ord(c) - ord('a') + 10
  of 'A'..'F': ord(c) - ord('A') + 10
  else: -1

proc percentDecode*(s: string): Option[string] =
  ## Decode percent-encoded ASCII. Returns `none` on malformed `%XX`.
  ##
  ## Also decodes `+` → ` ` (space) per the de-facto `application/x-www-
  ## form-urlencoded` convention used in real-world BIP-21 wallet UIs.
  ## BIP-21 itself does not mandate `+` decoding, but Bitcoin Core's
  ## QR-code path and every major mobile wallet (Bluewallet, Phoenix,
  ## Muun) emit `+` for spaces in `label=` and `message=`.
  var out_buf = newStringOfCap(s.len)
  var i = 0
  while i < s.len:
    let c = s[i]
    if c == '%':
      if i + 2 >= s.len:
        return none(string)
      let hi = hexNibble(s[i + 1])
      let lo = hexNibble(s[i + 2])
      if hi < 0 or lo < 0:
        return none(string)
      out_buf.add(char((hi shl 4) or lo))
      inc i, 3
    elif c == '+':
      out_buf.add(' ')
      inc i
    else:
      out_buf.add(c)
      inc i
  some(out_buf)

# ---------------------------------------------------------------------------
# Recognised param keys (case-folded to lower)
# ---------------------------------------------------------------------------

const
  KnownParams* = ["amount", "label", "message", "lightning", "pj", "pjos"]
    ## Params we accept under either bare or `req-` prefix.

proc isKnownParam(name: string): bool {.inline.} =
  ## Case-insensitive match against `KnownParams`.
  for p in KnownParams:
    if cmpIgnoreCase(p, name) == 0:
      return true
  false

# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------

type
  ParseOutcome* = object
    ## Detailed parse result. `isOk == true` ⇒ `value` populated;
    ## `isOk == false` ⇒ `error` populated.
    isOk*: bool
    value*: Bip21Uri
    error*: Bip21Error

proc okOutcome(uri: Bip21Uri): ParseOutcome {.inline.} =
  ParseOutcome(isOk: true, value: uri)

proc errOutcome(e: Bip21Error): ParseOutcome {.inline.} =
  ParseOutcome(isOk: false, error: e)

proc parseBip21UriDetailed*(input: string): ParseOutcome =
  ## Parse a BIP-21 URI and return either the parsed value or a typed error.
  ##
  ## Scheme matching is case-insensitive on the literal `bitcoin:` prefix
  ## (RFC 3986 §3.1 "Scheme names ... are case-insensitive"). The address
  ## body is preserved exactly.
  if input.len < len("bitcoin:") or
     cmpIgnoreCase(input[0 ..< len("bitcoin:")], "bitcoin:") != 0:
    return errOutcome(beNoScheme)

  let rest = input[len("bitcoin:") .. ^1]
  var address: string
  var query: string
  let qpos = rest.find('?')
  if qpos < 0:
    address = rest
    query = ""
  else:
    address = rest[0 ..< qpos]
    query = rest[qpos + 1 .. ^1]

  var uri = Bip21Uri(address: address)

  if query.len == 0:
    return okOutcome(uri)

  # Track which canonical params we've seen for duplicate detection.
  var seen = initTable[string, bool]()

  for kv in query.split('&'):
    if kv.len == 0:
      # `?&foo=bar` or trailing `&` — tolerate (de-facto behaviour of
      # browsers and most parsers; BIP-21 grammar doesn't permit but
      # nothing in the spec mandates reject).
      continue

    let eqPos = kv.find('=')
    var rawKey: string
    var rawVal: string
    if eqPos < 0:
      rawKey = kv
      rawVal = ""
    else:
      rawKey = kv[0 ..< eqPos]
      rawVal = kv[eqPos + 1 .. ^1]

    let keyDecoded = percentDecode(rawKey)
    if keyDecoded.isNone:
      return errOutcome(beBadPercentEncoding)
    let valDecoded = percentDecode(rawVal)
    if valDecoded.isNone:
      return errOutcome(beBadPercentEncoding)
    let key = keyDecoded.get
    let val = valDecoded.get

    # `req-` handling: if the suffix is not a known param, hard reject.
    var canonicalKey: string
    if key.len > 4 and cmpIgnoreCase(key[0 ..< 4], "req-") == 0:
      let suffix = key[4 .. ^1]
      if not isKnownParam(suffix):
        return errOutcome(beUnknownReqParam)
      canonicalKey = suffix.toLowerAscii()
    else:
      # Unknown non-`req-` params are silently ignored (BIP-21 spec).
      if not isKnownParam(key):
        continue
      canonicalKey = key.toLowerAscii()

    if seen.hasKeyOrPut(canonicalKey, true):
      return errOutcome(beDuplicateParam)

    case canonicalKey
    of "amount":
      # BIP-21 §"Specification": amountdecimal *DIGIT [ "." 1*DIGIT ]
      # Bitcoin Core's URI parser accepts up to 8 decimals (1 sat = 1e-8 BTC)
      # and rejects scientific notation. We use parseFloat which is more
      # permissive; callers that need strict BIP-21 conformance should
      # additionally check that `val` contains only `[0-9.]`.
      try:
        var amt: float
        let consumed = parseutils.parseFloat(val, amt, 0)
        if consumed != val.len or val.len == 0:
          return errOutcome(beBadAmount)
        if amt < 0:
          return errOutcome(beBadAmount)
        uri.amount = some(float64(amt))
      except ValueError:
        return errOutcome(beBadAmount)
    of "label":
      uri.label = some(val)
    of "message":
      uri.message = some(val)
    of "lightning":
      uri.lightning = some(val)
    of "pj":
      uri.pj = some(val)
    of "pjos":
      # BIP-78: `pjos=0` (output substitution allowed, default) or
      # `pjos=1` (output substitution disabled, sender requires its
      # outputs preserved verbatim).
      case val
      of "0": uri.pjos = some(false)
      of "1": uri.pjos = some(true)
      else: return errOutcome(beBadPjosFlag)
    else:
      # Should be unreachable — `canonicalKey` came from `KnownParams`.
      discard

  okOutcome(uri)

# ---------------------------------------------------------------------------
# Convenience wrapper (Option-flavoured)
# ---------------------------------------------------------------------------

proc parseBip21Uri*(input: string): Option[Bip21Uri] =
  ## Parse a BIP-21 URI string.
  ##
  ## Returns `some(Bip21Uri)` on success, `none(Bip21Uri)` on any structural
  ## failure (no scheme, malformed percent encoding, unknown `req-` param,
  ## bad amount, bad pjos flag, duplicate param). Callers wanting a more
  ## specific reason should use `parseBip21UriDetailed`.
  let r = parseBip21UriDetailed(input)
  if r.isOk: some(r.value) else: none(Bip21Uri)

# ---------------------------------------------------------------------------
# Narrow helpers (the test suite checks these symbols exist independently)
# ---------------------------------------------------------------------------

proc parseBip21PayJoinParam*(input: string): Option[string] =
  ## Extract the `pj=` endpoint URL from a BIP-21 URI, if present.
  ##
  ## Convenience wrapper for sender code that only cares about the PayJoin
  ## endpoint (W119 G28). Returns `none` if the URI is malformed OR if `pj=`
  ## was not supplied.
  let parsed = parseBip21Uri(input)
  if parsed.isNone:
    return none(string)
  parsed.get.pj

proc parseBip21OutputSubstitution*(input: string): Option[bool] =
  ## Extract the `pjos=` flag from a BIP-21 URI, if present (W119 G29).
  ##
  ## `true` ⇒ output substitution disabled (sender wants its outputs
  ## preserved verbatim, BIP-78 §"Output substitution").
  ## `false` ⇒ output substitution allowed (default).
  ## `none` ⇒ URI malformed OR `pjos=` not supplied.
  let parsed = parseBip21Uri(input)
  if parsed.isNone:
    return none(bool)
  parsed.get.pjos

proc payjoinOutputSubstitutionFlag*(uri: Bip21Uri): bool {.inline.} =
  ## Effective `disableoutputsubstitution` value from a parsed URI.
  ## Defaults to `false` (i.e. substitution allowed) when `pjos` is
  ## not supplied, matching BIP-78 §"Output substitution" defaults.
  if uri.pjos.isSome: uri.pjos.get else: false
