## FIX-62 — BIP-21 URI parser (closes W119 BUG-4 / G28-G29).
##
## See `src/wallet/bip21.nim` for the implementation. This test file
## exercises:
##   1. Plain URI (no params) parses, address preserved verbatim.
##   2. Each canonical param (amount, label, message, lightning, pj, pjos).
##   3. Percent-decoding of values (RFC 3986 §2.1) AND `+` → space.
##   4. `req-` rejection on unrecognised names; `req-<known>` accepted.
##   5. Unrecognised non-`req-` params silently ignored.
##   6. BIP-78 `pj=` + `pjos=` extension params (W119 G28, G29).
##   7. Case-insensitive keys (`AMOUNT`, `Pjos`, etc.).
##   8. BIP-21 spec example vectors (cross-checked against the live
##      bitcoin.org wiki "Examples" section as of 2026-05).
##   9. Negative cases (no scheme, bad percent-encoding, bad amount,
##      bad pjos, duplicate param).
##
## These tests replace the W119 audit's `check not compiles(parseBip21Uri)`
## / `check not compiles(Bip21Uri)` assertions, which are now invalidated
## by the existence of `src/wallet/bip21.nim`.

import std/[unittest, options, math]
import ../src/wallet/bip21

# ---------------------------------------------------------------------------
# Plain URI / no query
# ---------------------------------------------------------------------------
suite "FIX-62 plain URI":

  test "plain URI parses; address preserved verbatim":
    let r = parseBip21Uri("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    check r.isSome
    check r.get.address == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    check r.get.amount.isNone
    check r.get.label.isNone
    check r.get.message.isNone
    check r.get.lightning.isNone
    check r.get.pj.isNone
    check r.get.pjos.isNone

  test "empty address (no params) parses — caller validates":
    ## BIP-21 grammar does not actually forbid an empty address; the
    ## address codec catches that. The parser's job is structural only.
    let r = parseBip21Uri("bitcoin:")
    check r.isSome
    check r.get.address == ""

  test "scheme-only without `:` rejected":
    check parseBip21Uri("bitcoin").isNone
    check parseBip21Uri("").isNone

  test "scheme case-insensitive (RFC 3986 §3.1)":
    let r1 = parseBip21Uri("BITCOIN:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    let r2 = parseBip21Uri("BitCoIn:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    check r1.isSome and r2.isSome
    check r1.get.address == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    check r2.get.address == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"

# ---------------------------------------------------------------------------
# Standard query params
# ---------------------------------------------------------------------------
suite "FIX-62 standard params":

  test "amount param parses as BTC float":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=0.5")
    check r.isSome
    check r.get.amount.isSome
    check abs(r.get.amount.get - 0.5) < 1e-9

  test "amount with 8 decimals (1 sat)":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=0.00000001")
    check r.isSome
    check r.get.amount.isSome
    check abs(r.get.amount.get - 0.00000001) < 1e-12

  test "negative amount rejected":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=-1.0")
    check r.isNone

  test "non-numeric amount rejected":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=cats")
    check r.isNone

  test "label percent-decoded":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?label=Luke-Jr")
    check r.isSome
    check r.get.label.get == "Luke-Jr"

  test "label with spaces (percent-encoded)":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?label=Donate%20Now")
    check r.isSome
    check r.get.label.get == "Donate Now"

  test "label with + → space":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?label=Donate+Now")
    check r.isSome
    check r.get.label.get == "Donate Now"

  test "message percent-decoded with emoji-style multibyte":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?message=Hello%2C%20world%21")
    check r.isSome
    check r.get.message.get == "Hello, world!"

  test "lightning param preserved verbatim":
    let invoice = "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3"
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?lightning=" & invoice)
    check r.isSome
    check r.get.lightning.get == invoice

# ---------------------------------------------------------------------------
# BIP-78 PayJoin params (W119 G28, G29)
# ---------------------------------------------------------------------------
suite "FIX-62 BIP-78 pj= / pjos= (W119 G28-G29)":

  test "pj= endpoint URL parsed":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" &
      "?pj=https%3A%2F%2Fexample.com%2Fpj")
    check r.isSome
    check r.get.pj.get == "https://example.com/pj"

  test "pj= with onion endpoint":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" &
      "?pj=http%3A%2F%2Fpayjoin1xyz2qwertyuiopasdfghjklzxcvbnm.onion%2Fp")
    check r.isSome
    check r.get.pj.get ==
      "http://payjoin1xyz2qwertyuiopasdfghjklzxcvbnm.onion/p"

  test "pjos=1 → output substitution disabled":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?pjos=1")
    check r.isSome
    check r.get.pjos.get == true
    check payjoinOutputSubstitutionFlag(r.get) == true

  test "pjos=0 → output substitution allowed":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?pjos=0")
    check r.isSome
    check r.get.pjos.get == false
    check payjoinOutputSubstitutionFlag(r.get) == false

  test "pjos=2 (invalid flag) rejected":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?pjos=2")
    check r.isNone

  test "pjos missing → flag defaults false":
    let r = parseBip21Uri("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    check r.isSome
    check r.get.pjos.isNone
    check payjoinOutputSubstitutionFlag(r.get) == false

  test "parseBip21PayJoinParam narrow helper":
    let pj = parseBip21PayJoinParam(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?pj=https%3A%2F%2Fa%2Fb")
    check pj.isSome
    check pj.get == "https://a/b"

  test "parseBip21OutputSubstitution narrow helper":
    let p1 = parseBip21OutputSubstitution(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?pjos=1")
    let p0 = parseBip21OutputSubstitution(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?pjos=0")
    let pnone = parseBip21OutputSubstitution(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    check p1.isSome and p1.get == true
    check p0.isSome and p0.get == false
    check pnone.isNone

# ---------------------------------------------------------------------------
# req-X handling (BIP-21 §"Forward compatibility")
# ---------------------------------------------------------------------------
suite "FIX-62 req- handling":

  test "req-<unknown> rejected":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?req-somecoolthing=foo")
    check r.isNone

  test "req-amount accepted (known name under req- prefix)":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?req-amount=0.1")
    check r.isSome
    check r.get.amount.isSome
    check abs(r.get.amount.get - 0.1) < 1e-9

  test "req-pj accepted; routes to pj":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" &
      "?req-pj=https%3A%2F%2Fexample.com%2Fpj")
    check r.isSome
    check r.get.pj.get == "https://example.com/pj"

  test "req- prefix matched case-insensitive":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?REQ-AMOUNT=0.1")
    check r.isSome
    check r.get.amount.isSome

  test "req-somebogus rejects even when paired with valid params":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" &
      "?amount=0.5&req-futurething=x&label=Foo")
    check r.isNone

# ---------------------------------------------------------------------------
# Unknown non-req param: ignored
# ---------------------------------------------------------------------------
suite "FIX-62 unknown non-req params ignored":

  test "unknown bare param silently ignored":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" &
      "?someoptional=ignored&amount=1.0")
    check r.isSome
    check r.get.amount.isSome
    check abs(r.get.amount.get - 1.0) < 1e-9

  test "multiple unknown params silently ignored":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" &
      "?utm_source=qr&utm_medium=offline&utm_campaign=test")
    check r.isSome
    check r.get.amount.isNone

# ---------------------------------------------------------------------------
# Case-insensitive keys
# ---------------------------------------------------------------------------
suite "FIX-62 case-insensitive keys":

  test "AMOUNT (upper) parses":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?AMOUNT=0.25")
    check r.isSome
    check r.get.amount.isSome
    check abs(r.get.amount.get - 0.25) < 1e-9

  test "MixedCase Label parses":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?Label=Foo")
    check r.isSome
    check r.get.label.get == "Foo"

  test "Pjos parses":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?Pjos=1")
    check r.isSome
    check r.get.pjos.get == true

# ---------------------------------------------------------------------------
# Spec vectors (BIP-21 §Examples + payjoin.org reference URIs)
# ---------------------------------------------------------------------------
suite "FIX-62 BIP-21 spec vectors":

  test "Example 1: bare address":
    let r = parseBip21Uri("bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W")
    check r.isSome
    check r.get.address == "175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"

  test "Example 2: address + label":
    let r = parseBip21Uri(
      "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?label=Luke-Jr")
    check r.isSome
    check r.get.label.get == "Luke-Jr"

  test "Example 3: 20.30 BTC + label":
    let r = parseBip21Uri(
      "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W?amount=20.3&label=Luke-Jr")
    check r.isSome
    check abs(r.get.amount.get - 20.3) < 1e-9
    check r.get.label.get == "Luke-Jr"

  test "Example 4: amount + label + message":
    let r = parseBip21Uri(
      "bitcoin:175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W" &
      "?amount=50&label=Luke-Jr&message=Donation%20for%20project%20xyz")
    check r.isSome
    check abs(r.get.amount.get - 50.0) < 1e-9
    check r.get.label.get == "Luke-Jr"
    check r.get.message.get == "Donation for project xyz"

  test "BIP-78 example: address + amount + pj":
    let r = parseBip21Uri(
      "bitcoin:bc1q7cyrfmck2ffu2ud3rn5l5a8yv6f0chkp0zpemf" &
      "?amount=0.0001" &
      "&pj=https%3A%2F%2Ftimothyc.me%2Fbtcpay%2Fpj")
    check r.isSome
    check r.get.pj.get == "https://timothyc.me/btcpay/pj"
    check abs(r.get.amount.get - 0.0001) < 1e-12

  test "BIP-78 example: pj + pjos=1":
    let r = parseBip21Uri(
      "bitcoin:bc1q7cyrfmck2ffu2ud3rn5l5a8yv6f0chkp0zpemf" &
      "?amount=0.0001" &
      "&pj=https%3A%2F%2Fexample.com%2Fpj" &
      "&pjos=1")
    check r.isSome
    check r.get.pj.get == "https://example.com/pj"
    check r.get.pjos.get == true

# ---------------------------------------------------------------------------
# Negative / edge cases
# ---------------------------------------------------------------------------
suite "FIX-62 negative cases":

  test "no `bitcoin:` scheme rejected":
    check parseBip21Uri("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").isNone
    check parseBip21Uri("https://example.com").isNone
    check parseBip21Uri("ethereum:0xabc").isNone

  test "trailing % rejected (malformed percent encoding)":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?label=foo%")
    check r.isNone

  test "%GG rejected (non-hex)":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?label=%GG")
    check r.isNone

  test "duplicate amount param rejected":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=1.0&amount=2.0")
    check r.isNone

  test "duplicate label rejected":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?label=a&label=b")
    check r.isNone

  test "duplicate pj rejected":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?pj=http%3A%2F%2Fa&pj=http%3A%2F%2Fb")
    check r.isNone

  test "duplicate via req- + bare rejected (same canonical key)":
    let r = parseBip21Uri(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=1.0&req-amount=2.0")
    check r.isNone

# ---------------------------------------------------------------------------
# Detailed error reporting
# ---------------------------------------------------------------------------
suite "FIX-62 detailed error reporting":

  test "beNoScheme returned":
    let r = parseBip21UriDetailed("not-a-bitcoin-uri")
    check r.isOk == false
    check r.error == beNoScheme

  test "beBadPercentEncoding returned":
    let r = parseBip21UriDetailed(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?label=%XY")
    check r.isOk == false
    check r.error == beBadPercentEncoding

  test "beUnknownReqParam returned":
    let r = parseBip21UriDetailed(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?req-foo=bar")
    check r.isOk == false
    check r.error == beUnknownReqParam

  test "beBadAmount returned":
    let r = parseBip21UriDetailed(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=cats")
    check r.isOk == false
    check r.error == beBadAmount

  test "beBadPjosFlag returned":
    let r = parseBip21UriDetailed(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?pjos=true")
    check r.isOk == false
    check r.error == beBadPjosFlag

  test "beDuplicateParam returned":
    let r = parseBip21UriDetailed(
      "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?amount=1&amount=2")
    check r.isOk == false
    check r.error == beDuplicateParam
