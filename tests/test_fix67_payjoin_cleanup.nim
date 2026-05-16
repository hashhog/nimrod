## FIX-67 — BIP-78 PayJoin cleanup / W119 remaining-gates closure.
##
## Builds on FIX-65 (receiver foundation) + FIX-66 (sender + anti-snoop).
## This fix closes the remaining cleanup gates the W119 audit listed
## under "receiver-cleanup" + "sender-side hardening":
##
##   * G8  — receiver fee-output shrink MUST respect the dust floor
##           (`PayJoinDustThresholdSats`). A receiver that produces a
##           sub-dust output makes the proposal non-standard and the
##           sender's mempool refuses to relay it.
##   * G18 — receiver session table has a bounded-size sweep so a slow
##           Tor onion endpoint cannot accumulate TTL-fresh entries past
##           `PayJoinSessionsMaxSize`.  `sweepPayJoinSessions` is the
##           single entry point for receivers that want a steady-state
##           cleanup discipline.
##   * G19 — `payjoinReceive` now consumes the session automatically on
##           the successful proposal path (FIX-65 had the bookkeeping
##           helpers in place but no production code called them; the
##           audit's `pjeUnavailable` replay test only passed because
##           the test manually invoked `consumePayJoinSession`).  The
##           same Original PSBT, re-POSTed end-to-end, now raises
##           `pjeUnavailable` without any external poke.
##   * G21 — sender's `buildPayJoinPostUrl` guarantees `v=1` is in the
##           final URL.  BIP-78 §"BIP-78 endpoint" mandates the version
##           advertisement on every sender request; previously a caller
##           that omitted `extraQuery` would send a version-less URL
##           (the RPC handler always sets it, but `payjoinSenderRun`'s
##           default callers did not).
##   * G25 — `isPayJoinOnionEndpoint` + `PayJoinTorSocksPort` constant
##           make the Tor onion contract explicit.  The audit only
##           pinned the `payjoinOnionClient` surface; FIX-67 adds the
##           predicate so callers (and tests) can pre-flight the URL
##           without opening a socket, and surfaces the SOCKS5 port
##           assumption (`ALL_PROXY=socks5://127.0.0.1:9050`).
##   * G30 — same fix as G19 — they share the post-success invalidation
##           code path.  G30 asserts the bookkeeping AFTER consumption;
##           G19 asserts the rejection on the second POST.
##
## Reference:
##   bitcoin/bips/bip-0078.mediawiki §"Reuse protection"
##                                   §"BIP-78 endpoint"
##                                   §"Communicating with the receiver"
##   src/wallet/payjoin.nim (PayJoinDustThresholdSats, PayJoinTorSocksPort,
##                            sweepPayJoinSessions, isPayJoinOnionEndpoint,
##                            buildPayJoinPostUrl, payjoinReceive)
##   tests/test_fix65_payjoin_receiver.nim (helpers re-used in spirit)

import std/[unittest, options, strutils, times, tables]
import ../src/wallet/payjoin
import ../src/wallet/wallet
import ../src/wallet/psbt
import ../src/primitives/[types, serialize]
import ../src/crypto/[address, secp256k1, hashing]

# ---------------------------------------------------------------------------
# Local test helpers
#
# Mirror FIX-65/66 helpers but kept INDEPENDENT so this file can run
# in isolation (no implicit cross-file fixture coupling).
# ---------------------------------------------------------------------------

const TestMnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

proc makeReceiverWallet(value: int64 = 1_000_000): Wallet =
  var w = newWallet(TestMnemonic)
  w.addAccount(84, 0, 5)
  let key = w.accounts[0].externalKeys[0]
  let spk = scriptPubKeyForAddress(key.address)
  var idArr: array[32, byte]
  for i in 0 ..< 32: idArr[i] = byte((i + 7) and 0xff)
  let op = OutPoint(txid: TxId(idArr), vout: 0'u32)
  w.addUtxo(op,
    TxOut(value: Satoshi(value), scriptPubKey: spk),
    height = 100'i32, keyPath = key.path,
    isInternal = false, isCoinbase = false)
  w

proc makeSenderWallet(value: int64 = 500_000): Wallet =
  var seed: array[64, byte]
  for i in 0 ..< 64: seed[i] = byte(0x42 xor (i * 7))
  var w = newWalletFromSeed(seed)
  w.addAccount(84, 0, 5)
  let key = w.accounts[0].externalKeys[0]
  let spk = scriptPubKeyForAddress(key.address)
  var idArr: array[32, byte]
  for i in 0 ..< 32: idArr[i] = byte((i + 13) and 0xff)
  let op = OutPoint(txid: TxId(idArr), vout: 0'u32)
  w.addUtxo(op,
    TxOut(value: Satoshi(value), scriptPubKey: spk),
    height = 100'i32, keyPath = key.path,
    isInternal = false, isCoinbase = false)
  w

proc makeOriginalPsbt(sender: var Wallet,
                     senderUtxoValue: int64 = 500_000,
                     payToValue: int64 = 200_000,
                     changeValue: int64 = 299_500): Psbt =
  let senderKey = sender.accounts[0].externalKeys[0]
  let senderSpk = scriptPubKeyForAddress(senderKey.address)
  let receiverPayToSpk = senderSpk

  var idArr: array[32, byte]
  for i in 0 ..< 32: idArr[i] = byte((i + 13) and 0xff)
  let senderOutpoint = OutPoint(txid: TxId(idArr), vout: 0'u32)

  var tx = Transaction(
    version: 2'i32,
    inputs: @[TxIn(prevOut: senderOutpoint, scriptSig: @[],
                   sequence: 0xfffffffd'u32)],
    outputs: @[
      TxOut(value: Satoshi(payToValue), scriptPubKey: receiverPayToSpk),
      TxOut(value: Satoshi(changeValue), scriptPubKey: senderSpk)
    ],
    witnesses: @[@[]],
    lockTime: 0'u32)

  var p = createPsbt(tx)
  p.updateInput(0,
    TxOut(value: Satoshi(senderUtxoValue), scriptPubKey: senderSpk),
    isWitness = true)

  var workTx = tx
  let senderUtxo = WalletUtxo(
    outpoint: senderOutpoint,
    output: TxOut(value: Satoshi(senderUtxoValue), scriptPubKey: senderSpk),
    height: 100'i32,
    keyPath: senderKey.path,
    isInternal: false,
    isCoinbase: false)
  doAssert sender.signTransaction(workTx, @[senderUtxo])

  if workTx.witnesses.len > 0 and workTx.witnesses[0].len > 0:
    p.inputs[0].finalScriptWitness = workTx.witnesses[0]
  var sigTx = p.tx.get()
  if sigTx.witnesses.len == 0:
    sigTx.witnesses = newSeq[seq[seq[byte]]](sigTx.inputs.len)
  while sigTx.witnesses.len < sigTx.inputs.len:
    sigTx.witnesses.add(@[])
  sigTx.witnesses[0] = workTx.witnesses[0]
  p.tx = some(sigTx)
  p

# ---------------------------------------------------------------------------
# G19 + G30 — end-to-end replay rejection via payjoinReceive
# ---------------------------------------------------------------------------
suite "FIX-67 G19+G30 receiver auto-consume on success":

  test "payjoinReceive auto-marks the session consumed on first success":
    ## Pre-FIX-67: the receiver pipeline `rememberOriginal`-ed the
    ## session but never called `consumePayJoinSession`.  The W119
    ## audit's `pjeUnavailable` replay invariant therefore relied on
    ## the REST handler doing it externally — which it did not.
    ## Post-FIX-67: the very first successful proposal flips
    ## `consumed=true` in the same call.
    var sender = makeSenderWallet()
    var receiver = makeReceiverWallet()
    let originalPsbt = makeOriginalPsbt(sender)
    let originalTxid = originalPsbt.tx.get().txid()
    let sessions = newPayJoinSessionTable(ttlSeconds = 60)

    let proposalB64 = payjoinReceive(
      receiver, originalPsbt.toBase64(), "v=1", sessions, 200)
    check proposalB64.len > 0
    # The session table MUST now hold an entry for `originalTxid` with
    # `consumed=true`.
    check originalTxid in sessions.sessions
    check sessions.sessions[originalTxid].consumed == true

  test "payjoinReceive rejects a replayed Original PSBT END-TO-END (no manual consume)":
    ## This is the G19 invariant the W119 audit pinned: a malicious
    ## sender that re-posts the same Original PSBT MUST get
    ## `pjeUnavailable` from the receiver, with NO external bookkeeping
    ## by the test (the FIX-65 "error D" test cheated by calling
    ## `consumePayJoinSession` manually — that is the FIX-65 surface
    ## bug FIX-67 closes).
    var sender = makeSenderWallet()
    var receiver1 = makeReceiverWallet()
    let originalPsbt = makeOriginalPsbt(sender)
    let body = originalPsbt.toBase64()
    let sessions = newPayJoinSessionTable(ttlSeconds = 60)

    # First POST succeeds.
    let proposal1 = payjoinReceive(receiver1, body, "v=1", sessions, 200)
    check proposal1.len > 0

    # Second POST — fresh receiver wallet, SAME sessions table, SAME
    # Original PSBT body. MUST raise pjeUnavailable.
    var receiver2 = makeReceiverWallet()
    var observed: PayJoinErrorKind
    try:
      discard payjoinReceive(receiver2, body, "v=1", sessions, 200)
      check false   # MUST not reach here
    except PayJoinError as e:
      observed = e.kind
    check observed == pjeUnavailable

  test "payjoinReceive without a session table is a no-op for replay":
    ## When `sessions == nil`, the audit explicitly documents that
    ## replay protection is OFF (a unit-test convenience).  Pin this
    ## so a future refactor doesn't silently bind the consume call
    ## to a global table.
    var sender = makeSenderWallet()
    var receiver = makeReceiverWallet()
    let body = makeOriginalPsbt(sender).toBase64()
    # Two calls back-to-back must both succeed when sessions = nil.
    let a = payjoinReceive(receiver, body, "v=1", nil, 200)
    check a.len > 0
    var receiver2 = makeReceiverWallet()
    let b = payjoinReceive(receiver2, body, "v=1", nil, 200)
    check b.len > 0

# ---------------------------------------------------------------------------
# G18 — bounded sweep
# ---------------------------------------------------------------------------
suite "FIX-67 G18 sweepPayJoinSessions enforces size + TTL":

  test "sweep drops oldest when table exceeds maxSize":
    let tab = newPayJoinSessionTable(ttlSeconds = 3600)
    # Insert 5 entries with strictly-increasing firstSeen.
    for i in 0 ..< 5:
      var idArr: array[32, byte]
      idArr[0] = byte(i)
      rememberOriginal(tab, TxId(idArr), int64(1000 + i))
    check tab.sessions.len == 5

    # Cap to 3 — must drop the two oldest (i=0, i=1).
    sweepPayJoinSessions(tab, 1100, maxSize = 3)
    check tab.sessions.len == 3
    var oldestPresent: array[32, byte]
    oldestPresent[0] = byte(0)
    check TxId(oldestPresent) notin tab.sessions
    oldestPresent[0] = byte(1)
    check TxId(oldestPresent) notin tab.sessions
    # The youngest three are kept.
    for i in 2 ..< 5:
      var keep: array[32, byte]
      keep[0] = byte(i)
      check TxId(keep) in tab.sessions

  test "sweep runs TTL expiry first":
    let tab = newPayJoinSessionTable(ttlSeconds = 50)
    var idStale: array[32, byte]
    idStale[0] = 0xaa
    rememberOriginal(tab, TxId(idStale), 1000)
    var idFresh: array[32, byte]
    idFresh[0] = 0xbb
    rememberOriginal(tab, TxId(idFresh), 1180)

    # ttl = 50.  `now = 1200`:
    #   - stale entry at firstSeen=1000 is age 200 → expired.
    #   - fresh entry at firstSeen=1180 is age  20 → retained.
    sweepPayJoinSessions(tab, 1200)
    check TxId(idStale) notin tab.sessions
    check TxId(idFresh) in tab.sessions

  test "sweep is a no-op when below the cap":
    let tab = newPayJoinSessionTable(ttlSeconds = 3600)
    var id1: array[32, byte]
    id1[0] = 1
    rememberOriginal(tab, TxId(id1), 1000)
    sweepPayJoinSessions(tab, 1010, maxSize = PayJoinSessionsMaxSize)
    check tab.sessions.len == 1

  test "PayJoinSessionsMaxSize default is a sane large cap":
    check PayJoinSessionsMaxSize >= 256
    # Surface check — symbol exists and is a positive int.
    check PayJoinSessionsMaxSize > 0

# ---------------------------------------------------------------------------
# G21 — buildPayJoinPostUrl enforces v=1
# ---------------------------------------------------------------------------
suite "FIX-67 G21 buildPayJoinPostUrl injects v=<PAYJOIN_VERSION>":

  test "URL with no query gets v=1 appended":
    let u = buildPayJoinPostUrl("https://example.com/pj", "")
    check u == "https://example.com/pj?v=1"

  test "URL with non-version query gets v=1 prepended to extraQuery":
    let u = buildPayJoinPostUrl(
      "https://example.com/pj",
      "additionalfeeoutputindex=1&minfeerate=2")
    check u.contains("v=1")
    check u.contains("additionalfeeoutputindex=1")
    check u.contains("minfeerate=2")

  test "URL that already carries v=1 in endpointUrl is left alone":
    let u = buildPayJoinPostUrl(
      "https://example.com/pj?v=1&fee=0",
      "minfeerate=2")
    # No duplicate v=1.
    var count = 0
    var i = 0
    while i < u.len:
      let pos = u.find("v=", i)
      if pos < 0:
        break
      # Confirm it's a query-key v= (preceded by ? or & or at start).
      if pos == 0 or u[pos - 1] == '?' or u[pos - 1] == '&':
        inc count
      i = pos + 2
    check count == 1

  test "URL that already carries v=1 in extraQuery is left alone":
    let u = buildPayJoinPostUrl(
      "https://example.com/pj",
      "v=1&minfeerate=2")
    # Single v=1 — the prepend logic detects the existing one.
    var count = 0
    var i = 0
    while i < u.len:
      let pos = u.find("v=", i)
      if pos < 0:
        break
      if pos == 0 or u[pos - 1] == '?' or u[pos - 1] == '&':
        inc count
      i = pos + 2
    check count == 1

  test "no false-positive on keys that contain `v=` mid-name (`pjov=`)":
    # `pjov=xxx` has `v=` at offset 2, preceded by `o`, so MUST NOT
    # be treated as the version token.
    let u = buildPayJoinPostUrl(
      "https://example.com/pj?pjov=xxx", "")
    check u.contains("v=1")
    # And the original `pjov=xxx` is still present.
    check u.contains("pjov=xxx")

# ---------------------------------------------------------------------------
# G25 — isPayJoinOnionEndpoint + PayJoinTorSocksPort
# ---------------------------------------------------------------------------
suite "FIX-67 G25 onion endpoint predicate + Tor port":

  test "PayJoinTorSocksPort is the canonical 9050":
    check PayJoinTorSocksPort == 9050'u16

  test "isPayJoinOnionEndpoint accepts http://*.onion":
    check isPayJoinOnionEndpoint("http://abcdef.onion")
    check isPayJoinOnionEndpoint("http://abcdef.onion/payjoin")
    check isPayJoinOnionEndpoint("http://abcdef.onion:80/path?q=1")

  test "isPayJoinOnionEndpoint accepts https://*.onion (defense in depth)":
    check isPayJoinOnionEndpoint("https://abcdef.onion/pj")

  test "isPayJoinOnionEndpoint accepts a v3 56-char-looking onion":
    let v3 = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"
    check isPayJoinOnionEndpoint("http://" & v3)
    check isPayJoinOnionEndpoint("https://" & v3 & ":443/path")

  test "isPayJoinOnionEndpoint rejects clearnet URLs":
    check not isPayJoinOnionEndpoint("https://example.com/pj")
    check not isPayJoinOnionEndpoint("http://example.com/pj")
    check not isPayJoinOnionEndpoint("https://onion.example.com/pj")
    check not isPayJoinOnionEndpoint("https://example.onion.invalid/pj")

  test "isPayJoinOnionEndpoint rejects empty and malformed":
    check not isPayJoinOnionEndpoint("")
    check not isPayJoinOnionEndpoint("ftp://abc.onion/pj")
    check not isPayJoinOnionEndpoint("ssh://abc.onion")

  test "isPayJoinOnionEndpoint accepts bare *.onion (no scheme)":
    check isPayJoinOnionEndpoint("abcdef.onion")
    check isPayJoinOnionEndpoint("abcdef.onion:8443")

  test "payjoinOnionClient rejects clearnet (G25 production contract)":
    let req = PayJoinSendRequest(
      endpointUrl: "https://example.com/pj",
      originalPsbtBase64: "")
    let res = payjoinOnionClient(req)
    check res.outcome == psoNetworkError
    check res.receiverErrorMsg.contains("non-onion")

# ---------------------------------------------------------------------------
# G8 — receiver dust-floor protection
# ---------------------------------------------------------------------------
suite "FIX-67 G8 applyReceiverFeeDelta respects dust floor":

  test "applyReceiverFeeDelta refuses to shrink below PayJoinDustThresholdSats":
    var sender = makeSenderWallet()
    let receiverKey = makeReceiverWallet().accounts[0].externalKeys[0]
    let receiverSpk = scriptPubKeyForAddress(receiverKey.address)

    # Build an Original whose fee-output is just BARELY above the dust
    # floor: value = dust + 100.  A receiver delta of >100 sat would
    # push it below.
    var p = makeOriginalPsbt(sender,
      senderUtxoValue = 500_000,
      payToValue = 200_000,
      changeValue = PayJoinDustThresholdSats + 100)

    # A receiver wallet UTXO so we have something concrete to compute
    # the added fee from.
    var receiverIdArr: array[32, byte]
    for i in 0 ..< 32: receiverIdArr[i] = byte(i + 31)
    let utxos = @[WalletUtxo(
      outpoint: OutPoint(txid: TxId(receiverIdArr), vout: 0'u32),
      output: TxOut(value: Satoshi(100_000), scriptPubKey: receiverSpk),
      height: 100'i32, keyPath: receiverKey.path,
      isInternal: false, isCoinbase: false)]

    let opts = PayJoinReceiveOptions(
      version: PAYJOIN_VERSION,
      additionalFeeOutputIndex: some(1),
      maxAdditionalFeeContribution: Satoshi(10_000),
      minFeeRate: 1.0,
      disableOutputSubstitution: false)
    # Use an absurdly high fee rate to force a delta > 100 sats.
    let delta = applyReceiverFeeDelta(p, opts, 50.0, utxos)
    # FIX-67: refuse to apply the delta because the result would be
    # below dust — return 0, leave the PSBT unchanged.
    check delta == 0
    check int64(p.tx.get().outputs[1].value) ==
      PayJoinDustThresholdSats + 100  # unchanged

  test "applyReceiverFeeDelta still works when result stays above dust":
    var sender = makeSenderWallet()
    let receiverKey = makeReceiverWallet().accounts[0].externalKeys[0]
    let receiverSpk = scriptPubKeyForAddress(receiverKey.address)

    # Plenty of headroom: change = 50_000 sat, dust = 546 sat.
    var p = makeOriginalPsbt(sender,
      senderUtxoValue = 500_000,
      payToValue = 200_000,
      changeValue = 50_000)

    var receiverIdArr: array[32, byte]
    for i in 0 ..< 32: receiverIdArr[i] = byte(i + 31)
    let utxos = @[WalletUtxo(
      outpoint: OutPoint(txid: TxId(receiverIdArr), vout: 0'u32),
      output: TxOut(value: Satoshi(100_000), scriptPubKey: receiverSpk),
      height: 100'i32, keyPath: receiverKey.path,
      isInternal: false, isCoinbase: false)]

    let opts = PayJoinReceiveOptions(
      version: PAYJOIN_VERSION,
      additionalFeeOutputIndex: some(1),
      maxAdditionalFeeContribution: Satoshi(10_000),
      minFeeRate: 1.0,
      disableOutputSubstitution: false)
    let delta = applyReceiverFeeDelta(p, opts, 1.0, utxos)
    check delta > 0
    # Output was reduced by `delta`, and stays above dust.
    check int64(p.tx.get().outputs[1].value) == 50_000 - delta
    check int64(p.tx.get().outputs[1].value) >= PayJoinDustThresholdSats

  test "PayJoinDustThresholdSats matches the standard P2WPKH dust limit":
    # 546 sats is Bitcoin Core's standard dust threshold for a P2WPKH
    # output (Core's GetDustThreshold default).
    check PayJoinDustThresholdSats == 546

# ---------------------------------------------------------------------------
# Sanity — every FIX-67 surface symbol compiles
# ---------------------------------------------------------------------------
suite "FIX-67 surface check":

  test "all new FIX-67 symbols are exported":
    check compiles(PayJoinSessionsMaxSize)
    check compiles(PayJoinTorSocksPort)
    check compiles(PayJoinDustThresholdSats)
    check compiles(sweepPayJoinSessions)
    check compiles(isPayJoinOnionEndpoint)
    # And the helpers from FIX-65/66 we extended remain intact.
    check compiles(buildPayJoinPostUrl)
    check compiles(payjoinOnionClient)
    check compiles(consumePayJoinSession)
    check compiles(expirePayJoinSessions)
    check compiles(applyReceiverFeeDelta)
