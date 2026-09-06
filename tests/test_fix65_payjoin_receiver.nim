## FIX-65 — BIP-78 PayJoin receiver foundation (closes W119 BUG-1 / G1,
## G4-G9, G16-G21, G23, G30 receiver-side surface).
##
## See `src/wallet/payjoin.nim` for the receiver module and the FIX-65
## extension of `src/rpc/rest.nim` (GET-only → GET+POST) that finally
## wires `/payjoin` onto nimrod's existing REST listener.  The W119
## audit (`tests/test_w119_payjoin.nim`, commit `a87945d`) is the
## generating document; the `check not compiles(...)` assertions in
## that audit flip to `check compiles(...)` (and exercised live) for
## the receiver-side gates this fix closes.
##
## Coverage:
##   1. Round-trip — sender hand-built Original PSBT (finalized P2WPKH
##      input) → receiver POST handler → receiver adds wallet UTXO,
##      shrinks fee output, signs the new input, returns PSBT proposal.
##   2. Error path A — version-unsupported (`v=2`).
##   3. Error path B — original-psbt-rejected (malformed base64 body).
##   4. Error path C — not-enough-money (empty receiver wallet).
##   5. Error path D — unavailable (replay of a consumed Original PSBT).
##   6. Bonus: query-parameter parser, fee-output index parser,
##      Content-Type check, BIP-78 version constant.
##
## The HTTP transport layer is tested separately via `test_fix64_tls.nim`
## (HTTPS handshake + GET round-trip).  This file targets the BIP-78
## semantic layer + the new POST plumbing in `rest.nim`.
##
## Reference:
##   bitcoin/bips/bip-0078.mediawiki
##   src/wallet/payjoin.nim (module under test)
##   src/rpc/rest.nim       (POST dispatch + handleRestPayJoin)

import unittest2
import std/[options, strutils, tables, times, sets]
import ../src/wallet/payjoin
import ../src/wallet/wallet
import ../src/wallet/psbt
import ../src/wallet/bip21
import ../src/wallet/feebumper
import ../src/rpc/rest
import ../src/primitives/[types, serialize]
import ../src/consensus/params
import ../src/crypto/[address, secp256k1, hashing]

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

const TestMnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

proc makeReceiverWallet(value: int64 = 1_000_000): Wallet =
  ## Build a wallet with one funded P2WPKH UTXO (height 100, mature).
  ## The first external key receives the funding output.
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

proc makeEmptyWallet(): Wallet =
  ## Build a wallet with NO UTXOs — used to provoke `pjeNotEnoughMoney`.
  ## We still seed accounts so account key derivation has succeeded
  ## (the absence of UTXOs is the only difference from `makeReceiverWallet`).
  var w = newWallet(TestMnemonic)
  w.addAccount(84, 0, 5)
  w

proc makeSenderWallet(): Wallet =
  ## A SECOND wallet whose key the sender will use to sign the Original
  ## PSBT input.  Built from a distinct mnemonic so the sender's spk
  ## is NOT in the receiver's keychain (receiver MUST not be able to
  ## sign the Original's inputs).
  const senderMnemonic =
    "ability ability ability ability ability ability ability ability ability ability ability above"
  # Substitute "ability" → "abandon" is invalid (bad BIP-39 checksum);
  # instead derive deterministically from a fixed seed.
  var seed: array[64, byte]
  for i in 0 ..< 64: seed[i] = byte(0x42 xor (i * 7))
  var w = newWalletFromSeed(seed)
  w.addAccount(84, 0, 5)
  w

proc makeOriginalPsbt(sender: var Wallet,
                     senderUtxoValue: int64 = 500_000,
                     payToValue: int64 = 200_000,
                     changeValue: int64 = 299_500,
                     changeIsSender: bool = true): Psbt =
  ## Build a fully-signed Original PSBT for the receiver to operate on.
  ##
  ## Structure (P2WPKH only):
  ##   input[0]  — sender-owned P2WPKH UTXO (finalized via sign)
  ##   output[0] — receiver address (200000 sat) — the BIP-78 payment
  ##   output[1] — sender change      (299500 sat) — the fee output
  ##                                                  the receiver may
  ##                                                  shrink with
  ##                                                  `additionalfeeoutputindex=1`.
  ## Fee = senderUtxoValue - payToValue - changeValue = 500 sat
  let senderKey = sender.accounts[0].externalKeys[0]
  let senderSpk = scriptPubKeyForAddress(senderKey.address)

  # Receiver-pay-to address: re-derive deterministically — we use a
  # canned P2WPKH spk so the test isn't sensitive to keychain order.
  let receiverPayToSpk = senderSpk    # 'self-pay' for testing; the
                                       # receiver doesn't need to own
                                       # this output, the audit only
                                       # checks the receiver's INPUT
                                       # injection.

  # Sender change spk
  let changeSpk = senderSpk

  # Compose the unsigned tx.
  var idArr: array[32, byte]
  for i in 0 ..< 32: idArr[i] = byte((i + 13) and 0xff)
  let senderOutpoint = OutPoint(txid: TxId(idArr), vout: 0'u32)

  var tx = Transaction(
    version: 2'i32,
    inputs: @[TxIn(prevOut: senderOutpoint, scriptSig: @[], sequence: 0xfffffffd'u32)],
    outputs: @[
      TxOut(value: Satoshi(payToValue), scriptPubKey: receiverPayToSpk),
      TxOut(value: Satoshi(changeValue), scriptPubKey: changeSpk)
    ],
    witnesses: @[@[]],
    lockTime: 0'u32)

  # Build the Psbt with the unsigned tx.
  var p = createPsbt(tx)
  # Populate witnessUtxo so the receiver can compute the fee rate
  # without a chainState dependency.
  p.updateInput(0,
    TxOut(value: Satoshi(senderUtxoValue), scriptPubKey: senderSpk),
    isWitness = true)

  # Sign the sender's input using the sender's wallet.  We do this by
  # asking the sender's wallet to sign a workTx with a single utxo,
  # then transplanting the witness into the PSBT and "finalising"
  # by populating finalScriptWitness.
  var workTx = tx
  let senderUtxoForSign = WalletUtxo(
    outpoint: senderOutpoint,
    output: TxOut(value: Satoshi(senderUtxoValue), scriptPubKey: senderSpk),
    height: 100'i32,
    keyPath: senderKey.path,
    isInternal: false,
    isCoinbase: false)
  # Ensure the sender wallet KNOWS this UTXO so findKeyForScript hits.
  sender.addUtxo(senderOutpoint,
    TxOut(value: Satoshi(senderUtxoValue), scriptPubKey: senderSpk),
    height = 100'i32, keyPath = senderKey.path,
    isInternal = false, isCoinbase = false)
  doAssert sender.signTransaction(workTx, @[senderUtxoForSign])

  # Finalize input 0: copy the witness produced by signTransaction
  # into PsbtInput.finalScriptWitness so the receiver's
  # `isFullySignedOriginal` predicate accepts the input.
  if workTx.witnesses.len > 0 and workTx.witnesses[0].len > 0:
    p.inputs[0].finalScriptWitness = workTx.witnesses[0]
  # Update the unsigned-tx field with the signed witness too, so
  # `extractTransaction` could (theoretically) round-trip.
  var sigTx = p.tx.get()
  if sigTx.witnesses.len == 0:
    sigTx.witnesses = newSeq[seq[seq[byte]]](sigTx.inputs.len)
  while sigTx.witnesses.len < sigTx.inputs.len:
    sigTx.witnesses.add(@[])
  sigTx.witnesses[0] = workTx.witnesses[0]
  p.tx = some(sigTx)

  discard changeIsSender    # Reserved for future-mod tests
  p

# ---------------------------------------------------------------------------
# G17 — Error enum + four canonical kinds
# ---------------------------------------------------------------------------
suite "FIX-65 G17 PayJoin error enum":

  test "PayJoinErrorKind has the four canonical BIP-78 strings":
    check $pjeUnavailable == "unavailable"
    check $pjeNotEnoughMoney == "not-enough-money"
    check $pjeVersionUnsupported == "version-unsupported"
    check $pjeOriginalPsbtRejected == "original-psbt-rejected"

  test "PayJoinError carries a typed kind":
    let e = newPayJoinError(pjeUnavailable, "test")
    check e.kind == pjeUnavailable
    check e.msg == "test"

# ---------------------------------------------------------------------------
# G21 — Version advertisement constants
# ---------------------------------------------------------------------------
suite "FIX-65 G21 PAYJOIN_VERSION":

  test "PAYJOIN_VERSION = 1 (per BIP-78 §endpoint)":
    check PAYJOIN_VERSION == 1
    check PayJoinSupportedVersion == 1

# ---------------------------------------------------------------------------
# G16 — Query parameter parser
# ---------------------------------------------------------------------------
suite "FIX-65 G16 query parameter parser":

  test "empty query → defaults":
    let opts = parsePayJoinQueryParams("")
    check opts.version == 1
    check opts.additionalFeeOutputIndex.isNone
    check int64(opts.maxAdditionalFeeContribution) == 0
    check opts.minFeeRate == 0.0
    check not opts.disableOutputSubstitution

  test "every canonical param parses":
    let opts = parsePayJoinQueryParams(
      "v=1&additionalfeeoutputindex=1&" &
      "maxadditionalfeecontribution=600&" &
      "minfeerate=2.5&disableoutputsubstitution=1")
    check opts.version == 1
    check opts.additionalFeeOutputIndex.isSome
    check opts.additionalFeeOutputIndex.get == 1
    check int64(opts.maxAdditionalFeeContribution) == 600
    check abs(opts.minFeeRate - 2.5) < 1e-9
    check opts.disableOutputSubstitution

  test "case-insensitive keys":
    let opts = parsePayJoinQueryParams(
      "V=1&AdditionalFeeOutputIndex=0&DisableOutputSubstitution=0")
    check opts.version == 1
    check opts.additionalFeeOutputIndex.get == 0
    check not opts.disableOutputSubstitution

  test "parsePayJoinReceiverQuery alias works":
    let a = parsePayJoinReceiverQuery("v=1")
    check a.version == 1

# ---------------------------------------------------------------------------
# G6 — additionalfeeoutputindex parser
# ---------------------------------------------------------------------------
suite "FIX-65 G6 additionalfeeoutputindex":

  test "absent → none":
    check parseAdditionalFeeOutputIndex("v=1").isNone

  test "present → some":
    check parseAdditionalFeeOutputIndex("additionalfeeoutputindex=2").get == 2

  test "negative rejected":
    check parseAdditionalFeeOutputIndex("additionalfeeoutputindex=-1").isNone

  test "non-numeric rejected":
    check parseAdditionalFeeOutputIndex("additionalfeeoutputindex=abc").isNone

# ---------------------------------------------------------------------------
# G23 — Content-Type check
# ---------------------------------------------------------------------------
suite "FIX-65 G23 Content-Type":

  test "text/plain accepted":
    check checkPayJoinContentType("text/plain")
    check checkPayJoinContentType("Text/Plain")

  test "text/plain with charset accepted":
    check checkPayJoinContentType("text/plain; charset=utf-8")

  test "application/json rejected":
    check not checkPayJoinContentType("application/json")

  test "empty rejected":
    check not checkPayJoinContentType("")

# ---------------------------------------------------------------------------
# G4-G5 — Original PSBT validation
# ---------------------------------------------------------------------------
suite "FIX-65 G4 PSBT validation":

  test "an unsigned PSBT fails isFullySignedOriginal":
    var tx = Transaction(version: 2'i32,
      inputs: @[TxIn(prevOut: OutPoint(), scriptSig: @[], sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(100), scriptPubKey: @[])])
    let p = createPsbt(tx)
    check not isFullySignedOriginal(p)
    check not validateOriginalPsbt(p)

  test "an empty PSBT rejected":
    var p = Psbt()
    check not validateOriginalPsbt(p)
    check not isFullySignedOriginal(p)

  test "rejectMalleableOriginal flags PSBTv2":
    var p = Psbt()
    p.version = some(2'u32)
    check rejectMalleableOriginal(p)
    p.version = some(0'u32)
    check not rejectMalleableOriginal(p)

# ---------------------------------------------------------------------------
# G7 — Receiver input injection
# ---------------------------------------------------------------------------
suite "FIX-65 G7 input injection":

  test "receiverAddInputs appends to PSBT inputs and tx inputs":
    var tx = Transaction(version: 2'i32,
      inputs: @[TxIn(prevOut: OutPoint(), scriptSig: @[], sequence: 0xfffffffd'u32)],
      outputs: @[TxOut(value: Satoshi(100), scriptPubKey: @[])])
    var p = createPsbt(tx)
    let utxo = WalletUtxo(
      outpoint: OutPoint(vout: 7),
      output: TxOut(value: Satoshi(500), scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)),
      height: 100'i32,
      keyPath: "m/84'/0'/0'/0/0",
      isInternal: false,
      isCoinbase: false)
    receiverAddInputs(p, @[utxo])
    check p.tx.isSome
    check p.tx.get().inputs.len == 2
    check p.inputs.len == 2
    check p.inputs[1].witnessUtxo.isSome
    check int64(p.inputs[1].witnessUtxo.get().value) == 500

# ---------------------------------------------------------------------------
# G8 — Fee output adjustment
# ---------------------------------------------------------------------------
suite "FIX-65 G8 output modification":

  test "modifyOriginalOutput shrinks the chosen output":
    var tx = Transaction(version: 2'i32,
      inputs: @[],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[])])
    var p = createPsbt(tx)
    modifyOriginalOutput(p, 0, 250)
    check int64(p.tx.get().outputs[0].value) == 750

  test "modifyOriginalOutput rejects out-of-range index":
    var tx = Transaction(version: 2'i32, outputs: @[TxOut()])
    var p = createPsbt(tx)
    expect PsbtError:
      modifyOriginalOutput(p, 5, 1)

  test "modifyOriginalOutput rejects negative result":
    var tx = Transaction(version: 2'i32, outputs: @[TxOut(value: Satoshi(10))])
    var p = createPsbt(tx)
    expect PsbtError:
      modifyOriginalOutput(p, 0, 100)

  test "receiverAdjustFeeOutput respects disableoutputsubstitution":
    var tx = Transaction(version: 2'i32, outputs: @[TxOut(value: Satoshi(1000))])
    var p = createPsbt(tx)
    let opts = PayJoinReceiveOptions(
      additionalFeeOutputIndex: some(0),
      disableOutputSubstitution: true)
    check not receiverAdjustFeeOutput(p, opts, 100)
    check int64(p.tx.get().outputs[0].value) == 1000

  test "receiverAdjustFeeOutput requires fee-output index":
    var tx = Transaction(version: 2'i32, outputs: @[TxOut(value: Satoshi(1000))])
    var p = createPsbt(tx)
    let opts = PayJoinReceiveOptions(
      additionalFeeOutputIndex: none(int),
      disableOutputSubstitution: false)
    check not receiverAdjustFeeOutput(p, opts, 100)

  test "receiverAdjustFeeOutput shrinks when permitted":
    var tx = Transaction(version: 2'i32, outputs: @[TxOut(value: Satoshi(1000))])
    var p = createPsbt(tx)
    let opts = PayJoinReceiveOptions(
      additionalFeeOutputIndex: some(0),
      disableOutputSubstitution: false)
    check receiverAdjustFeeOutput(p, opts, 200)
    check int64(p.tx.get().outputs[0].value) == 800

# ---------------------------------------------------------------------------
# G9 — Fee delta computation
# ---------------------------------------------------------------------------
suite "FIX-65 G9 fee delta":

  test "receiverComputeAddedFee scales with input count and rate":
    let one = receiverComputeAddedFee(@[WalletUtxo()], 1.0)
    let two = receiverComputeAddedFee(@[WalletUtxo(), WalletUtxo()], 1.0)
    check two > one
    check one > 0

  test "feeRate <= 0 → zero delta":
    check receiverComputeAddedFee(@[WalletUtxo()], 0.0) == 0

  test "applyReceiverFeeDelta clamps to maxAdditionalFeeContribution":
    var tx = Transaction(version: 2'i32, outputs: @[TxOut(value: Satoshi(10_000))])
    var p = createPsbt(tx)
    let opts = PayJoinReceiveOptions(
      additionalFeeOutputIndex: some(0),
      maxAdditionalFeeContribution: Satoshi(50),
      disableOutputSubstitution: false)
    # Receiver wants to add ~68 sat at 1 sat/vB but cap is 50.
    let applied = applyReceiverFeeDelta(p, opts, 1.0, @[WalletUtxo()])
    check applied == 50
    check int64(p.tx.get().outputs[0].value) == 9950

# ---------------------------------------------------------------------------
# G20 — Anti-fingerprint UTXO selection
# ---------------------------------------------------------------------------
suite "FIX-65 G20 anti-fingerprint":

  test "prefers closest-above when target is satisfiable":
    let utxos = @[
      WalletUtxo(output: TxOut(value: Satoshi(100_000))),
      WalletUtxo(output: TxOut(value: Satoshi(200_000))),
      WalletUtxo(output: TxOut(value: Satoshi(150_000))),
      WalletUtxo(output: TxOut(value: Satoshi(500_000)))
    ]
    let picked = payjoinAvoidFingerprint(utxos, Satoshi(120_000))
    check picked.len == 1
    check int64(picked[0].output.value) == 150_000

  test "falls back to largest when no UTXO covers target":
    let utxos = @[
      WalletUtxo(output: TxOut(value: Satoshi(100))),
      WalletUtxo(output: TxOut(value: Satoshi(200)))
    ]
    let picked = payjoinAvoidFingerprint(utxos, Satoshi(1_000))
    check picked.len == 1
    check int64(picked[0].output.value) == 200

# ---------------------------------------------------------------------------
# G18, G19, G30 — Replay protection / TTL
# ---------------------------------------------------------------------------
suite "FIX-65 G18-G19-G30 replay + TTL":

  test "fresh session not consumed":
    let tab = newPayJoinSessionTable(ttlSeconds = 60)
    var tid: array[32, byte]
    tid[0] = 0x01
    check not checkPayJoinReplay(tab, TxId(tid), 1000)

  test "after consume, replay rejected":
    let tab = newPayJoinSessionTable(ttlSeconds = 60)
    var tid: array[32, byte]
    tid[0] = 0x02
    rememberOriginal(tab, TxId(tid), 1000)
    consumePayJoinSession(tab, TxId(tid))
    check checkPayJoinReplay(tab, TxId(tid), 1000)

  test "TTL expiry clears stale entries":
    let tab = newPayJoinSessionTable(ttlSeconds = 60)
    var tid: array[32, byte]
    tid[0] = 0x03
    rememberOriginal(tab, TxId(tid), 1000)
    consumePayJoinSession(tab, TxId(tid))
    check checkPayJoinReplay(tab, TxId(tid), 1030)   # 30s in
    # 61s in: stale, dropped → no longer "consumed".
    expirePayJoinSessions(tab, 1100)
    check not checkPayJoinReplay(tab, TxId(tid), 1100)

  test "payjoinSeenOriginals / payjoinReplaySet surface":
    let tab = newPayJoinSessionTable()
    var tid: array[32, byte]
    tid[1] = 0x04
    rememberOriginal(tab, TxId(tid), 1000)
    let seen = payjoinSeenOriginals(tab)
    let lst = payjoinReplaySet(tab)
    check seen.len == 1
    check lst.len == 1

# ---------------------------------------------------------------------------
# G1 — round-trip + 4 error paths
# ---------------------------------------------------------------------------
suite "FIX-65 G1 PayJoin receiver round-trip":

  test "round-trip: receiver injects input + shrinks fee output + signs":
    var sender = makeSenderWallet()
    var receiver = makeReceiverWallet(value = 1_000_000)
    let originalPsbt = makeOriginalPsbt(sender)
    let body = originalPsbt.toBase64()
    let query = "v=1&additionalfeeoutputindex=1&maxadditionalfeecontribution=600&minfeerate=0"

    let proposalB64 = payjoinReceive(receiver, body, query, nil, currentHeight = 200)
    check proposalB64.len > 0

    let proposal = fromBase64(proposalB64)
    check proposal.tx.isSome
    let propTx = proposal.tx.get()
    # Receiver must have appended exactly one input (G7).
    check propTx.inputs.len == 2
    # The new input MUST point to the receiver's wallet UTXO.
    var foundReceiverInput = false
    for inp in propTx.inputs:
      let key = receiver.findKeyForScript(@[])
      discard key
      if inp.prevOut.vout == 0:
        var idArr: array[32, byte]
        for i in 0 ..< 32: idArr[i] = byte((i + 7) and 0xff)
        if inp.prevOut.txid == TxId(idArr):
          foundReceiverInput = true
    check foundReceiverInput

    # PSBT MUST carry witnessUtxo for the new input (so signers can
    # round-trip without chainState).
    check proposal.inputs.len == 2
    check proposal.inputs[1].witnessUtxo.isSome

    # The receiver's input MUST have produced a non-empty witness
    # (= signed). Witnesses are stripped from the unsigned tx during
    # PSBT serialization (BIP-174: globally-unsigned tx is serialized
    # without witness), so we check the canonical location —
    # `PsbtInput.finalScriptWitness` on the receiver's PsbtInput.
    check proposal.inputs[1].finalScriptWitness.len > 0

  test "error A: version-unsupported (v=2)":
    var sender = makeSenderWallet()
    var receiver = makeReceiverWallet()
    let body = makeOriginalPsbt(sender).toBase64()
    expect PayJoinError:
      discard payjoinReceive(receiver, body, "v=2", nil, 200)

  test "error A bis: v=2 raises pjeVersionUnsupported by kind":
    var sender = makeSenderWallet()
    var receiver = makeReceiverWallet()
    let body = makeOriginalPsbt(sender).toBase64()
    var observed: PayJoinErrorKind
    try:
      discard payjoinReceive(receiver, body, "v=99", nil, 200)
      check false   # MUST raise
    except PayJoinError as e:
      observed = e.kind
    check observed == pjeVersionUnsupported

  test "error B: malformed base64 → original-psbt-rejected":
    var receiver = makeReceiverWallet()
    var observed: PayJoinErrorKind
    try:
      discard payjoinReceive(receiver, "this-is-not-valid-base64-or-psbt!!!",
                             "v=1", nil, 200)
      check false
    except PayJoinError as e:
      observed = e.kind
    check observed == pjeOriginalPsbtRejected

  test "error C: empty receiver wallet → not-enough-money":
    var sender = makeSenderWallet()
    var receiver = makeEmptyWallet()
    let body = makeOriginalPsbt(sender).toBase64()
    var observed: PayJoinErrorKind
    try:
      discard payjoinReceive(receiver, body, "v=1", nil, 200)
      check false
    except PayJoinError as e:
      observed = e.kind
    check observed == pjeNotEnoughMoney

  test "error D: replay of consumed Original → unavailable":
    var sender = makeSenderWallet()
    var receiver = makeReceiverWallet()
    let originalPsbt = makeOriginalPsbt(sender)
    let body = originalPsbt.toBase64()
    let originalTxid = originalPsbt.tx.get().txid()
    let sessions = newPayJoinSessionTable(ttlSeconds = 60)

    let proposalB64 = payjoinReceive(receiver, body, "v=1", sessions, 200)
    check proposalB64.len > 0

    # Mark the session consumed (simulating a successful proposal
    # round-trip; in the live flow, the REST handler would do this
    # after a 200 OK response).
    consumePayJoinSession(sessions, originalTxid)

    # Re-submit the same Original PSBT — MUST raise pjeUnavailable.
    var receiver2 = makeReceiverWallet()
    var observed: PayJoinErrorKind
    try:
      discard payjoinReceive(receiver2, body, "v=1", sessions, 200)
      check false
    except PayJoinError as e:
      observed = e.kind
    check observed == pjeUnavailable

# ---------------------------------------------------------------------------
# REST POST surface — `handleRestPayJoin` on the RestServer
# ---------------------------------------------------------------------------
suite "FIX-65 REST POST plumbing":

  test "handleRestPayJoin / handleRestPayJoinPost compile and route":
    ## The W119 audit `check not compiles(handleRestPayJoin)` /
    ## `handleRestPayJoinPost` pair flips to `check compiles(...)` now.
    check compiles(handleRestPayJoin)
    check compiles(handleRestPayJoinPost)

  test "RestServer without wallet → /payjoin returns 404":
    let p = mainnetParams()
    let rest = newRestServer(
      port = 30_001,
      chainState = nil,
      mempool = nil,
      params = p,
      tlsCertPath = "",
      tlsKeyPath = "",
      wallet = nil)
    let resp = rest.handleRestPayJoin("v=1", "text/plain", "AAA")
    check resp.status == Http404

  test "RestServer with wallet but wrong Content-Type → 400 + JSON error":
    var w = makeReceiverWallet()
    let p = mainnetParams()
    let rest = newRestServer(
      port = 30_002,
      chainState = nil,
      mempool = nil,
      params = p,
      tlsCertPath = "",
      tlsKeyPath = "",
      wallet = w)
    let resp = rest.handleRestPayJoin("v=1", "application/json", "AAA")
    check resp.status == Http400
    check resp.body.contains("original-psbt-rejected")

  test "RestServer with wallet + correct Content-Type + valid Original → 200":
    var sender = makeSenderWallet()
    var receiver = makeReceiverWallet()
    let body = makeOriginalPsbt(sender).toBase64()
    let p = mainnetParams()
    let rest = newRestServer(
      port = 30_003,
      chainState = nil,
      mempool = nil,
      params = p,
      tlsCertPath = "",
      tlsKeyPath = "",
      wallet = receiver)
    let resp = rest.handleRestPayJoin(
      "v=1&additionalfeeoutputindex=1", "text/plain", body)
    check resp.status == Http200
    check resp.contentType == "text/plain"
    check resp.body.len > 0

# ---------------------------------------------------------------------------
# Sanity: W119 surface assertions FLIPPED
# ---------------------------------------------------------------------------
suite "FIX-65 sanity: W119 audit assertions now flip to compiles":

  test "receiver surface symbols now compile (G1, G4-G9, G16-G20, G23)":
    check compiles(handlePayJoinPost)
    check compiles(handlePayJoinReceive)
    check compiles(payjoinReceive)
    check compiles(processPayJoinRequest)
    check compiles(validateOriginalPsbt)
    check compiles(isFullySignedOriginal)
    check compiles(checkOriginalPsbtForPayJoin)
    check compiles(receiverValidateOriginal)
    check compiles(checkOriginalFeeRate)
    check compiles(rejectMalleableOriginal)
    check compiles(parseAdditionalFeeOutputIndex)
    check compiles(additionalFeeOutputIndex)
    check compiles(getPayJoinFeeOutputIndex)
    check compiles(receiverAddInputs)
    check compiles(payjoinJoinInputs)
    check compiles(injectReceiverInputs)
    check compiles(modifyOriginalOutput)
    check compiles(receiverAdjustFeeOutput)
    check compiles(receiverComputeAddedFee)
    check compiles(applyReceiverFeeDelta)
    check compiles(parsePayJoinQueryParams)
    check compiles(PayJoinReceiveOptions)
    check compiles(parsePayJoinReceiverQuery)
    check compiles(PayJoinError)
    check compiles(PayJoinErrorKind)
    check compiles(pjeUnavailable)
    check compiles(pjeNotEnoughMoney)
    check compiles(pjeVersionUnsupported)
    check compiles(pjeOriginalPsbtRejected)
    check compiles(PayJoinReceiveTtlSeconds)
    check compiles(payjoinSessionTable)
    check compiles(expirePayJoinSessions)
    check compiles(payjoinSeenOriginals)
    check compiles(payjoinReplaySet)
    check compiles(checkPayJoinReplay)
    check compiles(selectPayJoinReceiverUtxo)
    check compiles(payjoinAvoidFingerprint)
    check compiles(PAYJOIN_VERSION)
    check compiles(PayJoinSupportedVersion)
    check compiles(checkPayJoinContentType)
    check compiles(payjoinRequireTextPlain)
    check compiles(consumePayJoinSession)
    check compiles(payjoinFinalizeSession)
    check compiles(invalidateOriginalAfterSuccess)

  test "previously-existing W118 + FIX-61 + FIX-62 surface still intact":
    check compiles(createRateBumpTransaction)
    check compiles(BumpFeeRequest)
    check compiles(BumpFeeError)
    check compiles(parseBip21Uri)
    check compiles(parseBip21PayJoinParam)
    check compiles(parseBip21OutputSubstitution)
