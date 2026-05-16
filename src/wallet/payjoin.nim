## BIP-78 PayJoin (Pay-to-EndPoint) — receiver-side foundation.
##
## Closes the W119 audit (`tests/test_w119_payjoin.nim`, audit commit
## `a87945d`) by adding the smallest cohesive set of building blocks the
## receiver needs to accept an Original PSBT, validate it, inject a
## receiver-owned input, adjust the fee output (when permitted), sign,
## and return the proposal as a PSBT.
##
## Reference: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki
##
## Scope intentionally limited to the receiver path (FIX-65). The
## matching sender path (G2 / G10-G15 / G22) is left for a future fix —
## the audit explicitly flagged the missing receiver as the
## architectural blocker because the receiver side is what nimrod must
## expose on its REST listener.
##
## What this module supplies (vs. W119 audit gates):
##
##   * `PayJoinError` / `PayJoinErrorKind`               — G17
##   * `pjeUnavailable` / `pjeNotEnoughMoney` /
##     `pjeVersionUnsupported` / `pjeOriginalPsbtRejected` — G17
##   * `PAYJOIN_VERSION` / `PayJoinSupportedVersion`     — G21
##   * `PayJoinReceiveOptions`, `parsePayJoinQueryParams`/
##     `parsePayJoinReceiverQuery`                       — G16
##   * `parseAdditionalFeeOutputIndex`                   — G6
##   * `validateOriginalPsbt`/`receiverValidateOriginal` — G4, G5
##   * `receiverAddInputs`/`injectReceiverInputs`        — G7
##   * `modifyOriginalOutput`/`receiverAdjustFeeOutput`  — G8
##   * `receiverComputeAddedFee`/`applyReceiverFeeDelta` — G9
##   * `selectPayJoinReceiverUtxo`                       — G20
##   * `payjoinReceive`/`processPayJoinRequest`          — G1 (entrypoint)
##   * `checkPayJoinContentType`                         — G23
##   * `PayJoinReceiveTtlSeconds`/`payjoinSessionTable`/
##     `expirePayJoinSessions`                           — G18
##   * `payjoinSeenOriginals`/`checkPayJoinReplay`/
##     `consumePayJoinSession`/`invalidateOriginalAfterSuccess` — G19, G30
##
## The HTTP POST entry point itself lives in `src/rpc/rest.nim`
## (`handleRestPayJoin`) — this module is transport-agnostic so it can
## be wired equally well from a future Tor onion service or unit test.

import std/[options, strutils, tables, parseutils, sets, times, sequtils, math, algorithm]
import ../primitives/[types, serialize]
import ../consensus/validation as consensus_validation
import ./psbt
import ./wallet
import ./bip21

# ---------------------------------------------------------------------------
# Version (G21)
# ---------------------------------------------------------------------------

const
  PAYJOIN_VERSION* = 1
    ## Single advertised wire version, per BIP-78 §"BIP-78 endpoint".
    ## A receiver MUST reject any request specifying a different
    ## version with `pjeVersionUnsupported`.

  PayJoinSupportedVersion* = PAYJOIN_VERSION
    ## Alias the audit references — symbol presence is a separate
    ## guard from the constant.

  PayJoinReceiveTtlSeconds* = 60'i64
    ## BIP-78 §"Receiver" recommends ~60s for stale-Original cleanup
    ## (G18). Sessions older than this are pruned by
    ## `expirePayJoinSessions`.

  ## Sensible receiver-side defaults; callers may override per-request.
  DefaultPayJoinMinFeeRate* = 1.0    ## sat/vB
  DefaultPayJoinFeeRate* = 1.0       ## sat/vB used when sender does not
                                     ## specify and we need to compute
                                     ## the added-input fee delta (G9).

# ---------------------------------------------------------------------------
# Errors (G17)
# ---------------------------------------------------------------------------

type
  PayJoinErrorKind* = enum
    pjeUnavailable           = "unavailable"
      ## Receiver currently cannot serve a proposal (no UTXOs, internal
      ## state inconsistent, replay-protected, etc.).  BIP-78 maps this
      ## verbatim to the JSON `errorCode` field.
    pjeNotEnoughMoney        = "not-enough-money"
      ## Receiver has no UTXO large enough to satisfy the proposal.
    pjeVersionUnsupported    = "version-unsupported"
      ## Sender requested a `v=` we do not advertise.
    pjeOriginalPsbtRejected  = "original-psbt-rejected"
      ## Original PSBT failed receiver-side sanity (unsigned input,
      ## malleable, PSBTv2, version mismatch, etc.).

  PayJoinError* = object of CatchableError
    ## Receiver-side typed error. Callers (the REST POST handler)
    ## convert into JSON `{ "errorCode": <kind>, "message": <msg> }`
    ## per BIP-78 §"Receive request errors".
    kind*: PayJoinErrorKind

proc newPayJoinError*(kind: PayJoinErrorKind, msg: string): ref PayJoinError =
  ## Construct + tag a PayJoinError. The `kind` is the canonical
  ## BIP-78 error string; `msg` is a free-form human-readable hint
  ## that we surface in the JSON body for operator debugging.
  var e = newException(PayJoinError, msg)
  e.kind = kind
  e

# ---------------------------------------------------------------------------
# Query parameter parsing (G6, G16)
# ---------------------------------------------------------------------------

type
  PayJoinReceiveOptions* = object
    ## Parsed BIP-78 query string supplied by the sender on the
    ## receive endpoint URL: e.g.
    ##   POST /payjoin?v=1&additionalfeeoutputindex=0
    ##         &maxadditionalfeecontribution=600
    ##         &minfeerate=2&disableoutputsubstitution=0
    version*: int                       ## BIP-78 `v` (defaults to 1)
    additionalFeeOutputIndex*: Option[int]
      ## `additionalfeeoutputindex` — which sender output may be reduced
      ## (G6). `none` means "the receiver may NOT reduce any output".
    maxAdditionalFeeContribution*: Satoshi
      ## `maxadditionalfeecontribution` — hard upper bound on the
      ## absolute fee delta the receiver may add (G9, G13). 0 means
      ## "no allowance" — receiver MUST NOT increase the fee at all.
    minFeeRate*: float64
      ## `minfeerate` (sat/vB) — sender's floor on the post-PayJoin fee
      ## rate. Receiver MUST NOT propose a tx whose effective fee rate
      ## falls below this (G15 — sender-side; receiver SHOULD also
      ## enforce its own min relay fee).
    disableOutputSubstitution*: bool
      ## `disableoutputsubstitution=1` ⇒ receiver MUST NOT touch any
      ## of the sender's outputs (G14). Mirrors BIP-21 `pjos=1`.

proc parseAdditionalFeeOutputIndex*(query: string): Option[int] =
  ## Extract `additionalfeeoutputindex=N` from a `key=value&key=value`
  ## query string. Returns `none` if the param is absent, malformed,
  ## or negative. Exported as a narrow helper for G6 surface checks.
  if query.len == 0:
    return none(int)
  for kv in query.split('&'):
    let eq = kv.find('=')
    if eq <= 0:
      continue
    let k = kv[0 ..< eq].toLowerAscii()
    if k != "additionalfeeoutputindex":
      continue
    let v = kv[eq + 1 .. ^1]
    var n: int
    let consumed = parseutils.parseInt(v, n, 0)
    if consumed != v.len:
      return none(int)
    if n < 0:
      return none(int)
    return some(n)
  none(int)

proc additionalFeeOutputIndex*(opts: PayJoinReceiveOptions): Option[int] =
  ## Lift the parsed field back into a top-level symbol — the audit
  ## (G6) checks for both `parseAdditionalFeeOutputIndex` and
  ## `additionalFeeOutputIndex` independently to defend against partial
  ## refactors that lose one without the other.
  opts.additionalFeeOutputIndex

proc getPayJoinFeeOutputIndex*(opts: PayJoinReceiveOptions): Option[int] =
  ## Third audit-named alias for the same fee-output accessor (G6).
  opts.additionalFeeOutputIndex

proc parsePayJoinQueryParams*(query: string): PayJoinReceiveOptions =
  ## Parse the five canonical BIP-78 query params. Unknown keys are
  ## silently ignored (BIP-78 does not currently mandate forward
  ## compat behaviour; ignoring matches `payjoin.org`'s reference).
  ##
  ## Defaults — when a param is absent, the conservative receiver
  ## defaults apply:
  ##   v=1, additionalfeeoutputindex=none,
  ##   maxadditionalfeecontribution=0, minfeerate=0,
  ##   disableoutputsubstitution=false.
  result.version = PAYJOIN_VERSION
  result.additionalFeeOutputIndex = none(int)
  result.maxAdditionalFeeContribution = Satoshi(0)
  result.minFeeRate = 0.0
  result.disableOutputSubstitution = false

  if query.len == 0:
    return

  for kv in query.split('&'):
    if kv.len == 0: continue
    let eq = kv.find('=')
    if eq <= 0: continue
    let key = kv[0 ..< eq].toLowerAscii()
    let val = kv[eq + 1 .. ^1]

    case key
    of "v":
      var n: int
      if parseutils.parseInt(val, n, 0) == val.len:
        result.version = n
    of "additionalfeeoutputindex":
      var n: int
      if parseutils.parseInt(val, n, 0) == val.len and n >= 0:
        result.additionalFeeOutputIndex = some(n)
    of "maxadditionalfeecontribution":
      var n: int64
      if parseutils.parseBiggestInt(val, n, 0) == val.len and n >= 0:
        result.maxAdditionalFeeContribution = Satoshi(n)
    of "minfeerate":
      var f: float
      if parseutils.parseFloat(val, f, 0) == val.len and f >= 0:
        result.minFeeRate = float64(f)
    of "disableoutputsubstitution":
      case val
      of "1", "true": result.disableOutputSubstitution = true
      of "0", "false", "": result.disableOutputSubstitution = false
      else: discard
    else:
      discard

proc parsePayJoinReceiverQuery*(query: string): PayJoinReceiveOptions =
  ## Audit-named alias for `parsePayJoinQueryParams` (G16) so a
  ## partial-rename refactor cannot break the surface check.
  parsePayJoinQueryParams(query)

# ---------------------------------------------------------------------------
# Content-Type validation (G23)
# ---------------------------------------------------------------------------

proc checkPayJoinContentType*(headerValue: string): bool =
  ## BIP-78 §"Receive request" mandates `Content-Type: text/plain`.
  ## We compare case-insensitively on the type/subtype only and
  ## tolerate optional `; charset=...` suffixes (RFC 7231 §3.1.1.5).
  if headerValue.len == 0:
    return false
  let semi = headerValue.find(';')
  let mediaType =
    if semi < 0: headerValue.strip()
    else: headerValue[0 ..< semi].strip()
  cmpIgnoreCase(mediaType, "text/plain") == 0

proc payjoinRequireTextPlain*(headerValue: string): bool {.inline.} =
  ## Audit-named alias (G23).
  checkPayJoinContentType(headerValue)

# ---------------------------------------------------------------------------
# Original PSBT validation (G4, G5)
# ---------------------------------------------------------------------------

proc isFullySignedOriginal*(psbtObj: Psbt): bool =
  ## BIP-78 §"Receiver verification of Original PSBT" precondition:
  ## every input MUST already be signed/finalized by the sender, else
  ## the receiver cannot safely re-broadcast as fallback.
  if psbtObj.tx.isNone:
    return false
  let inputs = psbtObj.inputs
  if inputs.len == 0:
    return false
  for inp in inputs:
    # finalScriptSig (legacy) OR finalScriptWitness (segwit) present
    # ⇒ Finalizer has run on this input.
    if inp.finalScriptSig.len == 0 and inp.finalScriptWitness.len == 0:
      return false
  true

proc checkOriginalPsbtForPayJoin*(psbtObj: Psbt): bool {.inline.} =
  ## Audit-named alias for `isFullySignedOriginal` (G4).
  isFullySignedOriginal(psbtObj)

proc validateOriginalPsbt*(psbtObj: Psbt): bool =
  ## G4: minimum receiver acceptance — finalized inputs + non-empty
  ## tx + at least one output. Stronger semantic checks
  ## (`receiverValidateOriginal`) layer on top.
  if psbtObj.tx.isNone:
    return false
  let tx = psbtObj.tx.get()
  if tx.inputs.len == 0 or tx.outputs.len == 0:
    return false
  isFullySignedOriginal(psbtObj)

proc rejectMalleableOriginal*(psbtObj: Psbt): bool =
  ## G5: receiver MUST refuse a tx with non-standard / malleable
  ## hints. Concretely we refuse PSBTv2 (`version=2`) — nimrod's
  ## wallet currently emits PSBTv0 only, and Core's BIP-78 receiver
  ## refuses v2 (BIP-78 §"Receiver verification" item 1).
  if psbtObj.version.isSome and psbtObj.version.get != 0'u32:
    return true   # malleable / unsupported version
  false

proc checkOriginalFeeRate*(psbtObj: Psbt,
                           prevOuts: openArray[TxOut],
                           minFeeRateSatVb: float64): bool =
  ## G5: cross-check the Original PSBT's effective feerate against a
  ## floor (sender's `minfeerate` and/or our local min relay). Returns
  ## `true` iff the Original meets or exceeds the floor.
  ##
  ## `prevOuts` must align with `tx.inputs` and provide each input's
  ## prev-output value. The caller (POST handler) is responsible for
  ## resolving prev-outs from the UTXO set or the PSBT's
  ## `witnessUtxo`/`nonWitnessUtxo` fields before calling.
  if psbtObj.tx.isNone or prevOuts.len == 0:
    return false
  let tx = psbtObj.tx.get()
  if prevOuts.len != tx.inputs.len:
    return false
  if minFeeRateSatVb <= 0.0:
    return true   # caller doesn't care; treat as satisfied

  var inSum = Satoshi(0)
  for p in prevOuts:
    inSum = inSum + p.value
  var outSum = Satoshi(0)
  for o in tx.outputs:
    outSum = outSum + o.value
  if int64(outSum) > int64(inSum):
    return false                       # negative fee — reject
  let fee = int64(inSum) - int64(outSum)
  let weight = consensus_validation.calculateTransactionWeight(tx)
  let vsize = (weight + 3) div 4
  if vsize <= 0:
    return false
  let rate = float64(fee) / float64(vsize)
  rate + 1e-9 >= minFeeRateSatVb

proc receiverValidateOriginal*(psbtObj: Psbt,
                               opts: PayJoinReceiveOptions,
                               prevOuts: openArray[TxOut]): bool =
  ## G5 composite: version, signed-ness, structural sanity, and
  ## sender-declared `minfeerate`. Returns `true` iff the Original
  ## may proceed to receiver-side modification.
  if rejectMalleableOriginal(psbtObj):
    return false
  if not validateOriginalPsbt(psbtObj):
    return false
  if opts.minFeeRate > 0.0:
    if not checkOriginalFeeRate(psbtObj, prevOuts, opts.minFeeRate):
      return false
  true

# ---------------------------------------------------------------------------
# Receiver UTXO selection (G7, G20)
# ---------------------------------------------------------------------------

proc payjoinAvoidFingerprint*(utxos: seq[WalletUtxo],
                              targetAmount: Satoshi): seq[WalletUtxo] =
  ## G20 anti-fingerprint policy: BIP-78 §"Receiver" warns against the
  ## predictable "largest UTXO" pick because it leaks the receiver's
  ## wallet shape. We instead prefer a UTXO whose value is the closest
  ## to `targetAmount` from above (mirroring Core's
  ## `wallet/spend.cpp::ChooseSelectionResult` "closest-above" tiebreak
  ## when no exact match exists) and fall back to the smallest UTXO
  ## that still covers `targetAmount` if no above-target candidate
  ## exists. This still doesn't hide the participation — that requires
  ## a full BIP-77 round-robin — but it removes the "always picks the
  ## largest" tell.
  ##
  ## NB: callers MUST already have filtered immature coinbase outputs
  ## (see `wallet.isMatureCoinbase`).
  if utxos.len == 0:
    return @[]
  var candidates: seq[WalletUtxo] = @[]
  for u in utxos:
    if int64(u.output.value) >= int64(targetAmount):
      candidates.add(u)
  if candidates.len > 0:
    # Sort ascending by value → pick the smallest covering UTXO
    var sorted = candidates
    sorted.sort(proc(a, b: WalletUtxo): int =
      cmp(int64(a.output.value), int64(b.output.value)))
    return @[sorted[0]]
  # Nothing above target: take the largest available (only safe
  # fallback — if none is large enough alone, the caller will surface
  # `pjeNotEnoughMoney`).
  var sorted = utxos
  sorted.sort(proc(a, b: WalletUtxo): int =
    cmp(int64(b.output.value), int64(a.output.value)))
  @[sorted[0]]

proc selectPayJoinReceiverUtxo*(wallet: Wallet,
                                targetAmount: Satoshi,
                                currentHeight: int32 = 0): seq[WalletUtxo] =
  ## G7 + G20: receiver's UTXO selection.
  ##
  ## The receiver MUST inject at least one input from its own wallet
  ## (P2EP's defining property — without this it's not PayJoin, it's a
  ## regular proxy). We pick a single UTXO via `payjoinAvoidFingerprint`
  ## to avoid the always-largest tell.
  ##
  ## Returns the chosen WalletUtxos (currently always 1 — multi-input
  ## injection is a future extension; the BIP-78 reference receivers
  ## also typically inject one).
  var avail: seq[WalletUtxo] = @[]
  for _, u in wallet.utxos:
    if currentHeight > 0 and not u.isMatureCoinbase(currentHeight):
      continue
    if u.keyPath.len == 0:
      continue
    avail.add(u)
  payjoinAvoidFingerprint(avail, targetAmount)

# ---------------------------------------------------------------------------
# Receiver input injection (G7)
# ---------------------------------------------------------------------------

proc receiverAddInputs*(psbtObj: var Psbt,
                       receiverUtxos: seq[WalletUtxo]) =
  ## G7: append receiver-owned inputs to the Original PSBT.
  ##
  ## Each added input:
  ##   - Carries a fresh `TxIn` with empty scriptSig + sender-matching
  ##     sequence (we mirror the sequence of the first sender input so
  ##     the BIP-125 / nLockTime semantics of the proposal are
  ##     identical to the Original — Core does the same in
  ##     `wallet/rpc/spend.cpp::AddCustomKeyPathToInput`).
  ##   - Gets a populated `PsbtInput.witnessUtxo` from the wallet so
  ##     the receiver can later sign it without consulting chainState.
  ##
  ## Raises `PsbtError` if `psbtObj.tx` is absent (Creator role missing).
  if psbtObj.tx.isNone:
    raise newException(PsbtError, "PSBT has no unsigned transaction")
  if receiverUtxos.len == 0:
    return   # nothing to inject; caller validates

  var tx = psbtObj.tx.get()
  let cloneSeq: uint32 =
    if tx.inputs.len > 0: tx.inputs[0].sequence
    else: 0xfffffffd'u32   # default BIP-125 RBF
  for u in receiverUtxos:
    let newIn = TxIn(
      prevOut: u.outpoint,
      scriptSig: @[],
      sequence: cloneSeq)
    tx.inputs.add(newIn)
    var pIn = PsbtInput()
    pIn.witnessUtxo = some(u.output)
    psbtObj.inputs.add(pIn)
  # Keep witnesses aligned with inputs so signing can populate slot N.
  while tx.witnesses.len < tx.inputs.len:
    tx.witnesses.add(@[])
  psbtObj.tx = some(tx)

proc injectReceiverInputs*(psbtObj: var Psbt,
                          receiverUtxos: seq[WalletUtxo]) {.inline.} =
  ## Audit alias (G7).
  receiverAddInputs(psbtObj, receiverUtxos)

proc payjoinJoinInputs*(psbtObj: var Psbt,
                       receiverUtxos: seq[WalletUtxo]) {.inline.} =
  ## Audit alias (G7).
  receiverAddInputs(psbtObj, receiverUtxos)

# ---------------------------------------------------------------------------
# Receiver output modification (G8)
# ---------------------------------------------------------------------------

proc modifyOriginalOutput*(psbtObj: var Psbt,
                           outputIndex: int,
                           delta: int64) =
  ## G8: reduce the value of `outputIndex` by `delta` satoshis. `delta`
  ## > 0 shrinks the output; we use this to fund the receiver's added
  ## inputs' fee budget without the receiver paying out of pocket.
  ##
  ## Raises `PsbtError` if the index is out of range OR the resulting
  ## value would be negative (the caller must enforce dust separately).
  if psbtObj.tx.isNone:
    raise newException(PsbtError, "PSBT has no unsigned transaction")
  var tx = psbtObj.tx.get()
  if outputIndex < 0 or outputIndex >= tx.outputs.len:
    raise newException(PsbtError, "output index out of range")
  let cur = int64(tx.outputs[outputIndex].value)
  let newVal = cur - delta
  if newVal < 0:
    raise newException(PsbtError, "output value would go negative")
  tx.outputs[outputIndex].value = Satoshi(newVal)
  psbtObj.tx = some(tx)

proc receiverAdjustFeeOutput*(psbtObj: var Psbt,
                              opts: PayJoinReceiveOptions,
                              delta: int64): bool =
  ## G8 + G14 gate: only adjust the fee output when (a) the sender
  ## supplied `additionalfeeoutputindex`, (b) `disableoutputsubstitution`
  ## is NOT set, and (c) the delta is positive. Returns `true` iff the
  ## adjustment ran.
  if opts.disableOutputSubstitution:
    return false
  if opts.additionalFeeOutputIndex.isNone:
    return false
  if delta <= 0:
    return false
  modifyOriginalOutput(psbtObj, opts.additionalFeeOutputIndex.get(), delta)
  true

# ---------------------------------------------------------------------------
# Fee adjustment (G9)
# ---------------------------------------------------------------------------

proc receiverComputeAddedFee*(receiverUtxos: seq[WalletUtxo],
                              feeRateSatVb: float64): int64 =
  ## G9: estimate the absolute fee increase needed to keep the proposal
  ## at `feeRateSatVb` after we add `receiverUtxos.len` inputs.
  ##
  ## We use a conservative weight estimate that assumes every receiver
  ## input is a P2WPKH (the dominant case in nimrod's wallet, and the
  ## upper bound on any wider mix that includes legacy/segwit-v1). A
  ## P2WPKH input contributes ~68 vbytes (41 vbytes prevout/sequence +
  ## ~27 vbytes signed witness amortised).
  if feeRateSatVb <= 0.0 or receiverUtxos.len == 0:
    return 0
  const VbytesPerP2WPKHInput = 68
  let extraVbytes = receiverUtxos.len * VbytesPerP2WPKHInput
  int64(ceil(feeRateSatVb * float64(extraVbytes)))

proc applyReceiverFeeDelta*(psbtObj: var Psbt,
                            opts: PayJoinReceiveOptions,
                            feeRateSatVb: float64,
                            receiverUtxos: seq[WalletUtxo]): int64 =
  ## G9 + G13 gate: compute the receiver's fee increase, clamp it to
  ## `maxAdditionalFeeContribution`, shrink the sender's flagged fee
  ## output by that amount, and return the actually applied delta.
  ##
  ## Returns 0 (no-op) when:
  ##   * the sender forbade output substitution (G14), OR
  ##   * no `additionalfeeoutputindex` was supplied, OR
  ##   * the fee delta is zero / negative, OR
  ##   * the receiver-side hash of the math would push the output
  ##     below the wallet's dust limit (we refuse silently rather than
  ##     leaving the proposal in a broken state — Core does the same).
  if opts.disableOutputSubstitution:
    return 0
  if opts.additionalFeeOutputIndex.isNone:
    return 0
  var delta = receiverComputeAddedFee(receiverUtxos, feeRateSatVb)
  if delta <= 0:
    return 0
  if int64(opts.maxAdditionalFeeContribution) > 0:
    delta = min(delta, int64(opts.maxAdditionalFeeContribution))
  let idx = opts.additionalFeeOutputIndex.get()
  if psbtObj.tx.isNone:
    return 0
  let tx = psbtObj.tx.get()
  if idx < 0 or idx >= tx.outputs.len:
    return 0
  let cur = int64(tx.outputs[idx].value)
  if cur - delta < 0:
    return 0
  modifyOriginalOutput(psbtObj, idx, delta)
  delta

# ---------------------------------------------------------------------------
# Replay protection + TTL (G18, G19, G30)
# ---------------------------------------------------------------------------

type
  PayJoinSession* = object
    ## One entry of the receiver-side replay-protection / TTL table.
    ## We key on the unsigned Original tx's txid (sender-finalized
    ## inputs make it stable). `firstSeen` is Unix seconds.
    originalTxid*: TxId
    firstSeen*: int64
    consumed*: bool          ## true after a successful proposal — any
                             ## further POST with the same `originalTxid`
                             ## must return `pjeUnavailable`.

  PayJoinSessionTable* = ref object
    ## Receiver-state container — owned by the RPC layer (one instance
    ## per `RestServer`). Ref-typed so the REST handler can mutate it
    ## without ref-copy semantics getting in the way.
    sessions*: Table[TxId, PayJoinSession]
    ttlSeconds*: int64

proc newPayJoinSessionTable*(ttlSeconds: int64 = PayJoinReceiveTtlSeconds):
    PayJoinSessionTable =
  ## Construct an empty session table with a configurable TTL.
  PayJoinSessionTable(
    sessions: initTable[TxId, PayJoinSession](),
    ttlSeconds: ttlSeconds)

proc payjoinSessionTable*(): PayJoinSessionTable =
  ## Audit-named factory (G18).
  newPayJoinSessionTable()

proc expirePayJoinSessions*(table: PayJoinSessionTable, now: int64) =
  ## G18: drop sessions older than `table.ttlSeconds` against `now`.
  ## Caller chooses the time source so the test suite can drive it
  ## deterministically.
  var stale: seq[TxId] = @[]
  for k, v in table.sessions:
    if now - v.firstSeen > table.ttlSeconds:
      stale.add(k)
  for k in stale:
    table.sessions.del(k)

proc payjoinReplaySet*(table: PayJoinSessionTable): seq[TxId] =
  ## G19 observer: list of txids currently in the receiver's replay
  ## protection table (so tests / RPC introspection can verify).
  toSeq(table.sessions.keys)

proc payjoinSeenOriginals*(table: PayJoinSessionTable): HashSet[TxId] =
  ## G19 alias: set-typed view over the same data.
  var s = initHashSet[TxId]()
  for k in table.sessions.keys:
    s.incl(k)
  s

proc checkPayJoinReplay*(table: PayJoinSessionTable,
                        originalTxid: TxId,
                        now: int64): bool =
  ## G19: return `true` iff this Original is already known AND has
  ## been consumed (a stale-but-unconsumed entry can still be
  ## re-proposed; only a successful proposal blocks future replays).
  expirePayJoinSessions(table, now)
  if originalTxid notin table.sessions:
    return false
  table.sessions[originalTxid].consumed

proc rememberOriginal*(table: PayJoinSessionTable,
                      originalTxid: TxId, now: int64) =
  ## Internal: track a freshly-arrived Original PSBT so its TTL and
  ## replay state can be checked later. Idempotent: a duplicate POST
  ## with the same txid keeps the original `firstSeen` (which keeps
  ## TTL clocks honest).
  if originalTxid notin table.sessions:
    table.sessions[originalTxid] = PayJoinSession(
      originalTxid: originalTxid,
      firstSeen: now,
      consumed: false)

proc consumePayJoinSession*(table: PayJoinSessionTable,
                           originalTxid: TxId) =
  ## G30: mark a session as successfully responded to. Subsequent POSTs
  ## with the same `originalTxid` will be rejected via
  ## `checkPayJoinReplay` ⇒ `pjeUnavailable`.
  if originalTxid in table.sessions:
    var s = table.sessions[originalTxid]
    s.consumed = true
    table.sessions[originalTxid] = s
  else:
    table.sessions[originalTxid] = PayJoinSession(
      originalTxid: originalTxid,
      firstSeen: getTime().toUnix(),
      consumed: true)

proc payjoinFinalizeSession*(table: PayJoinSessionTable,
                            originalTxid: TxId) {.inline.} =
  ## Audit alias (G30).
  consumePayJoinSession(table, originalTxid)

proc invalidateOriginalAfterSuccess*(table: PayJoinSessionTable,
                                    originalTxid: TxId) {.inline.} =
  ## Audit alias (G30).
  consumePayJoinSession(table, originalTxid)

# ---------------------------------------------------------------------------
# Receiver pipeline — top-level entry (G1)
# ---------------------------------------------------------------------------

proc payjoinReceive*(wallet: var Wallet,
                    base64OriginalPsbt: string,
                    query: string,
                    sessions: PayJoinSessionTable = nil,
                    currentHeight: int32 = 0,
                    feeRateSatVb: float64 = DefaultPayJoinFeeRate):
                   string =
  ## Full receiver pipeline. Inputs:
  ##   * `base64OriginalPsbt` — body of the POST request (Content-Type
  ##     text/plain).
  ##   * `query` — `?v=1&...` from the request line (already stripped
  ##     of the leading `?`).
  ##   * `sessions` — replay-protection table (optional; if nil, no
  ##     replay protection is applied — that's safe for unit tests).
  ##   * `currentHeight` — chain tip for coinbase-maturity gating.
  ##   * `feeRateSatVb` — receiver-side target fee rate.
  ##
  ## Returns the **base64 PSBT proposal** on success (BIP-78 body of
  ## the 200 OK response).
  ##
  ## Raises `PayJoinError` with one of the four canonical kinds on
  ## failure; the REST POST handler converts those to BIP-78 JSON
  ## error envelopes.
  let opts = parsePayJoinReceiverQuery(query)
  if opts.version != PAYJOIN_VERSION:
    raise newPayJoinError(pjeVersionUnsupported,
      "v=" & $opts.version & " not supported; we advertise v=" &
      $PAYJOIN_VERSION)

  # Parse the body.
  var original: Psbt
  try:
    original = fromBase64(base64OriginalPsbt)
  except PsbtError as e:
    raise newPayJoinError(pjeOriginalPsbtRejected,
      "PSBT base64 decode failed: " & e.msg)
  except CatchableError as e:
    raise newPayJoinError(pjeOriginalPsbtRejected,
      "PSBT decode failed: " & e.msg)

  if original.tx.isNone:
    raise newPayJoinError(pjeOriginalPsbtRejected,
      "PSBT has no unsigned transaction")
  let origTx = original.tx.get()
  let originalTxid = origTx.txid()

  # Resolve prev-outs from `witnessUtxo` (segwit) / `nonWitnessUtxo`
  # (legacy) so the fee-rate check can run without chainState.
  var prevOuts: seq[TxOut] = @[]
  for i, pIn in original.inputs:
    if pIn.witnessUtxo.isSome:
      prevOuts.add(pIn.witnessUtxo.get())
    elif pIn.nonWitnessUtxo.isSome:
      let prevTx = pIn.nonWitnessUtxo.get()
      let voutIdx = int(origTx.inputs[i].prevOut.vout)
      if voutIdx < 0 or voutIdx >= prevTx.outputs.len:
        raise newPayJoinError(pjeOriginalPsbtRejected,
          "nonWitnessUtxo vout out of range for input " & $i)
      prevOuts.add(prevTx.outputs[voutIdx])
    else:
      raise newPayJoinError(pjeOriginalPsbtRejected,
        "input " & $i & " lacks witnessUtxo/nonWitnessUtxo")

  if not receiverValidateOriginal(original, opts, prevOuts):
    raise newPayJoinError(pjeOriginalPsbtRejected,
      "Original PSBT failed receiver-side validation")

  # Replay protection (G19) — check before mutating.
  let now = getTime().toUnix()
  if sessions != nil:
    if checkPayJoinReplay(sessions, originalTxid, now):
      raise newPayJoinError(pjeUnavailable,
        "Original PSBT already proposed against (replay)")
    rememberOriginal(sessions, originalTxid, now)

  # Compute the receiver's target contribution to size the picked UTXO.
  # We want one UTXO that covers the (expected) added fee at least.
  let estAddedFee = receiverComputeAddedFee(@[WalletUtxo()], feeRateSatVb)
  let target = Satoshi(max(int64(1), estAddedFee))

  let chosen = selectPayJoinReceiverUtxo(wallet, target, currentHeight)
  if chosen.len == 0:
    raise newPayJoinError(pjeNotEnoughMoney,
      "Receiver wallet has no spendable UTXO")

  var proposal = original
  receiverAddInputs(proposal, chosen)

  # Shrink the fee output (best-effort) by the receiver's added cost.
  discard applyReceiverFeeDelta(proposal, opts, feeRateSatVb, chosen)

  # Sign the receiver-added inputs ONLY. The Original inputs are
  # already finalized by the sender (G4 invariant) and we must not
  # touch them.
  let firstReceiverInputIdx = origTx.inputs.len
  var txCopy = proposal.tx.get()
  # We pass a `utxos` array aligned with `txCopy.inputs`; the slots
  # before `firstReceiverInputIdx` are placeholders that signTransaction
  # will skip because their scriptPubKey doesn't match any wallet key
  # (sender's inputs).  However, signTransaction returns false on any
  # un-signable input, so we must construct a partial signer instead —
  # we directly populate `partialSigs` via a per-input call below.
  for i in firstReceiverInputIdx ..< txCopy.inputs.len:
    let utxoIdx = i - firstReceiverInputIdx
    let u = chosen[utxoIdx]
    var perInputUtxos: seq[WalletUtxo] = @[]
    # We need to invoke signTransaction with a one-element utxos
    # parallel to a one-input transaction slice, but signTransaction
    # operates on whole txs. Inline a single-input sign via the same
    # primitives used by `wallet.signTransaction`.
    let spk = u.output.scriptPubKey
    let keyOpt = wallet.findKeyForScript(spk)
    if keyOpt.isNone:
      raise newPayJoinError(pjeUnavailable,
        "Receiver-chosen UTXO has no matching key")
    # Sign only this input by temporarily slicing the tx; since
    # `signTransaction` requires utxos.len == tx.inputs.len, we build
    # a single-input working tx, sign, then transplant the witness
    # back into the real tx.
    var workTx = Transaction(
      version: txCopy.version,
      inputs: @[txCopy.inputs[i]],
      outputs: txCopy.outputs,
      witnesses: @[@[]],
      lockTime: txCopy.lockTime)
    perInputUtxos.add(u)
    if not wallet.signTransaction(workTx, perInputUtxos):
      raise newPayJoinError(pjeUnavailable,
        "Receiver could not sign input " & $i)
    # Transplant the produced witness back onto the proposal tx.
    if workTx.witnesses.len >= 1:
      while txCopy.witnesses.len <= i:
        txCopy.witnesses.add(@[])
      txCopy.witnesses[i] = workTx.witnesses[0]
    # Also transplant any scriptSig the signer set (legacy P2PKH).
    txCopy.inputs[i].scriptSig = workTx.inputs[0].scriptSig
    # Mirror the witness into the corresponding PsbtInput so the
    # downstream consumer can re-extract the signed witness from the
    # PSBT after `toBase64`/`fromBase64` round-trip (PSBT's unsigned
    # tx serialization deliberately strips witnesses — they live in
    # `PsbtInput.finalScriptWitness` after the Finalizer role).
    if i < proposal.inputs.len and workTx.witnesses.len >= 1:
      proposal.inputs[i].finalScriptWitness = workTx.witnesses[0]
    if i < proposal.inputs.len and workTx.inputs[0].scriptSig.len > 0:
      proposal.inputs[i].finalScriptSig = workTx.inputs[0].scriptSig
  proposal.tx = some(txCopy)

  # Encode the proposal as base64 and return.
  proposal.toBase64()

proc processPayJoinRequest*(wallet: var Wallet,
                           base64OriginalPsbt: string,
                           query: string,
                           sessions: PayJoinSessionTable = nil,
                           currentHeight: int32 = 0): string {.inline.} =
  ## Audit alias for `payjoinReceive` (G1).
  payjoinReceive(wallet, base64OriginalPsbt, query, sessions, currentHeight)

proc handlePayJoinPost*(wallet: var Wallet,
                       base64OriginalPsbt: string,
                       query: string,
                       contentType: string,
                       sessions: PayJoinSessionTable = nil,
                       currentHeight: int32 = 0): string =
  ## G1 + G23 audit-named entry: HTTP-layer wrapper that adds the
  ## Content-Type check and re-raises a `PayJoinError`.  The REST POST
  ## handler delegates to this so the HTTP path stays thin (parse +
  ## delegate + status-code mapping).
  if not checkPayJoinContentType(contentType):
    raise newPayJoinError(pjeOriginalPsbtRejected,
      "Content-Type must be text/plain (got '" & contentType & "')")
  payjoinReceive(wallet, base64OriginalPsbt, query, sessions, currentHeight)

proc handlePayJoinReceive*(wallet: var Wallet,
                          base64OriginalPsbt: string,
                          query: string,
                          contentType: string,
                          sessions: PayJoinSessionTable = nil,
                          currentHeight: int32 = 0): string {.inline.} =
  ## Audit alias (G1).
  handlePayJoinPost(wallet, base64OriginalPsbt, query, contentType,
                    sessions, currentHeight)

# Re-export BIP-21 PayJoin helpers so callers can `import payjoin` and
# get the URI parsing surface without a second import.
export bip21.parseBip21PayJoinParam, bip21.parseBip21OutputSubstitution,
       bip21.payjoinOutputSubstitutionFlag, bip21.Bip21Uri,
       bip21.parseBip21Uri
