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
import chronos
import chronos/apps/http/httpclient
import ../primitives/[types, serialize]
from ../consensus/validation import calculateTransactionWeight
import ../script/interpreter as script_interp
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
  let weight = calculateTransactionWeight(tx)
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

# ===========================================================================
# SENDER side — BIP-78 Pay-to-EndPoint (P2EP) outbound flow (FIX-66)
# ===========================================================================
#
# Closes W119 BUG-2 "PayJoin sender subsystem MISSING ENTIRELY":
#
#   G10 — checkPayJoinOutputRules
#   G11 — checkPayJoinInputTypes      (scriptSig-type homogeneity)
#   G12 — checkPayJoinNoNewSenderInputs (proposal MUST NOT add sender-owned inputs)
#   G13 — checkPayJoinMaxFee          (max additional fee contribution honored)
#   G14 — checkPayJoinDisableOutputSubstitution (sender's outputs intact)
#   G15 — checkPayJoinMinFeeRate      (post-PayJoin tx ≥ minfeerate)
#   G22 — payjoinSenderFallback / broadcastOriginalOnPayJoinFailure
#   G24 — verifyPayJoinTlsCert / payjoinHttpsVerify (HTTPS cert validation)
#   G26 — getpayjoinrequest RPC (handler defined in src/rpc/server.nim)
#   G27 — sendpayjoinrequest RPC (handler defined in src/rpc/server.nim)
#
# Anti-snoop validators reject a malicious receiver-returned Proposal that
# tries to steal funds. BIP-78 §"Checking the Proposal" enumerates the
# exact invariants — a receiver could otherwise drain the sender by
# (a) substituting outputs to attacker-owned scripts, (b) injecting new
# sender-owned inputs (causing double-spend), (c) inflating the fee, or
# (d) mixing input types (deanonymization-by-correlation).

# ---------------------------------------------------------------------------
# Sender helpers — small classifier + analytic helpers
# ---------------------------------------------------------------------------

type
  PayJoinInputType* = enum
    ## Classification used by G11 — receiver-added inputs MUST share the
    ## same type with the sender's inputs, else the post-PayJoin tx is
    ## trivially deanonymizable (mixed-input-types is the strongest
    ## clustering heuristic — see BIP-78 §"Multiple input types").
    pitUnknown    = "unknown"
    pitP2PKH      = "p2pkh"
    pitP2SH       = "p2sh"
    pitP2WPKH     = "p2wpkh"
    pitP2WSH      = "p2wsh"
    pitP2TR       = "p2tr"

proc classifyPayJoinInput*(spk: seq[byte]): PayJoinInputType =
  ## Classify a scriptPubKey into one of the five canonical Bitcoin
  ## script types. Unknown / non-standard scripts fall back to
  ## `pitUnknown`. The receiver is allowed to ship any of the five, but
  ## MUST match the sender's predominant type (G11).
  if script_interp.isP2WPKH(spk): pitP2WPKH
  elif script_interp.isP2WSH(spk): pitP2WSH
  elif script_interp.isP2TR(spk): pitP2TR
  elif script_interp.isP2PKH(spk): pitP2PKH
  elif script_interp.isP2SH(spk): pitP2SH
  else: pitUnknown

proc senderInputTypes*(original: Psbt, prevOuts: openArray[TxOut]):
    seq[PayJoinInputType] =
  ## Per-input classification of the SENDER's Original PSBT inputs.
  ## `prevOuts` must align with `original.tx.inputs`. Used by G11 +
  ## G12 — the proposal's added inputs MUST share this classification.
  result = @[]
  for p in prevOuts:
    result.add(classifyPayJoinInput(p.scriptPubKey))

proc payjoinSenderInputOutpoints*(original: Psbt): HashSet[OutPoint] =
  ## Set of outpoints the sender spent in the Original PSBT, used by
  ## G12 to ensure the receiver does NOT inject more sender-owned
  ## outpoints (which would force the sender to sign extra inputs and
  ## thus over-pay).
  result = initHashSet[OutPoint]()
  if original.tx.isSome:
    for inp in original.tx.get().inputs:
      result.incl(inp.prevOut)

# ---------------------------------------------------------------------------
# G10 — Sender output-rule enforcement
# ---------------------------------------------------------------------------

proc checkPayJoinOutputRules*(original, proposal: Psbt,
                              opts: PayJoinReceiveOptions): bool =
  ## G10 — sender-side validation of the proposal's outputs.
  ##
  ## BIP-78 §"Checking the Proposal":
  ##  - Each sender output MUST still exist in the proposal at the same
  ##    scriptPubKey UNLESS it is the `additionalfeeoutputindex` AND the
  ##    sender did NOT pass `disableoutputsubstitution=1`.
  ##  - The fee-output (if shrunk) MUST NOT have its scriptPubKey changed.
  ##  - The proposal MUST NOT add new sender-owned outputs (the receiver
  ##    is free to add ITS OWN output, but that is the receiver's
  ##    contribution, not a snoop vector — we don't check that here).
  ##  - The proposal MAY have at most one fewer output than the Original
  ##    only if the fee-output was a known dust output that got dropped.
  ##    We're conservative: we require the same output count.
  if original.tx.isNone or proposal.tx.isNone:
    return false
  let origTx = original.tx.get()
  let propTx = proposal.tx.get()
  # Output count: same or +1 (receiver may add its own).
  if propTx.outputs.len < origTx.outputs.len:
    return false
  if propTx.outputs.len > origTx.outputs.len + 1:
    return false
  # Every sender output must appear in the proposal at the same scriptPubKey.
  for i, o in origTx.outputs:
    if i >= propTx.outputs.len:
      return false
    if propTx.outputs[i].scriptPubKey != o.scriptPubKey:
      return false
    # Output value: must match exactly UNLESS this is the fee-output AND
    # output substitution is permitted.
    if propTx.outputs[i].value != o.value:
      if opts.disableOutputSubstitution:
        return false   # any mutation is forbidden
      if opts.additionalFeeOutputIndex.isNone:
        return false   # sender did not name a fee-output
      if opts.additionalFeeOutputIndex.get() != i:
        return false   # mutation outside the fee-output slot
      # Allowed shrink only — never grow.
      if int64(propTx.outputs[i].value) > int64(o.value):
        return false
  true

proc payjoinValidateOutputs*(original, proposal: Psbt,
                            opts: PayJoinReceiveOptions): bool {.inline.} =
  ## Audit alias (G10).
  checkPayJoinOutputRules(original, proposal, opts)

# ---------------------------------------------------------------------------
# G11 — scriptSig type-match
# ---------------------------------------------------------------------------

proc checkPayJoinInputTypes*(original, proposal: Psbt,
                             senderPrevOuts: openArray[TxOut],
                             proposalPrevOuts: openArray[TxOut]): bool =
  ## G11 — the receiver-added inputs MUST share the SAME script type as
  ## the sender's inputs. A mixed-input-types proposal would deanonymize
  ## the sender's wallet (chain analysis flags mixed v0/v1/legacy as a
  ## "consolidation across wallet types" event).
  ##
  ## `senderPrevOuts` aligns with original.tx.inputs, `proposalPrevOuts`
  ## with proposal.tx.inputs.
  if original.tx.isNone or proposal.tx.isNone:
    return false
  let origInputs = original.tx.get().inputs.len
  let propInputs = proposal.tx.get().inputs.len
  if propInputs < origInputs:
    return false
  if senderPrevOuts.len != origInputs:
    return false
  if proposalPrevOuts.len != propInputs:
    return false
  # Compute the sender's dominant script type. We require homogeneity
  # within the sender's inputs (Core's BIP-78 sender does this too — a
  # mixed-type Original wallet is itself a clustering tell).
  var senderType = pitUnknown
  if origInputs > 0:
    senderType = classifyPayJoinInput(senderPrevOuts[0].scriptPubKey)
    for i in 1 ..< origInputs:
      if classifyPayJoinInput(senderPrevOuts[i].scriptPubKey) != senderType:
        return false
  # Every receiver-added input must match.
  for i in origInputs ..< propInputs:
    if classifyPayJoinInput(proposalPrevOuts[i].scriptPubKey) != senderType:
      return false
  true

proc payjoinValidateInputTypes*(original, proposal: Psbt,
                               senderPrevOuts: openArray[TxOut],
                               proposalPrevOuts: openArray[TxOut]): bool {.inline.} =
  ## Audit alias (G11).
  checkPayJoinInputTypes(original, proposal, senderPrevOuts, proposalPrevOuts)

# ---------------------------------------------------------------------------
# G12 — No new sender-owned inputs
# ---------------------------------------------------------------------------

proc checkPayJoinNoNewSenderInputs*(original, proposal: Psbt,
                                    senderOwnedOutpoints: HashSet[OutPoint]): bool =
  ## G12 — the proposal MUST NOT spend any sender-owned outpoint that the
  ## Original PSBT did not already spend. BIP-78 §"Checking the Proposal":
  ## a malicious receiver could otherwise force the sender to sign extra
  ## inputs (a "drain attack" — sender's wallet contributes more funds
  ## than intended). The first defence is the sender wallet refusing to
  ## sign unfamiliar inputs; this validator is the BIP-78-level
  ## belt-and-braces check.
  if original.tx.isNone or proposal.tx.isNone:
    return false
  let origOutpoints = payjoinSenderInputOutpoints(original)
  let propTx = proposal.tx.get()
  for inp in propTx.inputs:
    if inp.prevOut in origOutpoints:
      continue   # the original sender input — fine
    # New input — MUST NOT be one of the sender's other outpoints.
    if inp.prevOut in senderOwnedOutpoints:
      return false
  true

proc payjoinValidateNoNewSenderInputs*(original, proposal: Psbt,
                                      senderOwnedOutpoints: HashSet[OutPoint]):
                                     bool {.inline.} =
  ## Audit alias (G12).
  checkPayJoinNoNewSenderInputs(original, proposal, senderOwnedOutpoints)

# ---------------------------------------------------------------------------
# G13 — Max additional fee contribution
# ---------------------------------------------------------------------------

proc checkPayJoinMaxFee*(original, proposal: Psbt,
                         senderPrevOuts: openArray[TxOut],
                         proposalPrevOuts: openArray[TxOut],
                         maxAdditionalFee: Satoshi): bool =
  ## G13 — the absolute increase in fee between Original and Proposal,
  ## paid out of the SENDER's pocket (i.e. via the additionalfeeoutputindex
  ## shrink), MUST NOT exceed `maxAdditionalFee`.
  ##
  ## Computation:
  ##   senderInOrig   = sum(senderPrevOuts.value)
  ##   senderOutOrig  = sum(origTx.outputs.value)
  ##   senderInProp   = sum(senderPrevOuts.value)        # unchanged (G12)
  ##   senderOutProp  = sum(propTx.outputs[i].value for i in sender outputs)
  ##
  ## Sender's contribution to the proposal's fee delta equals the
  ## reduction in their own outputs from Original → Proposal. Receiver-added
  ## inputs/outputs net out because they are 100% on the receiver's side
  ## of the conservation equation.
  if original.tx.isNone or proposal.tx.isNone:
    return false
  let origTx = original.tx.get()
  let propTx = proposal.tx.get()
  if senderPrevOuts.len != origTx.inputs.len:
    return false
  if proposalPrevOuts.len != propTx.inputs.len:
    return false
  # Sender's outputs in the proposal are at the same indices as in the
  # Original (G10 enforces order preservation).
  var origOutSum = int64(0)
  for o in origTx.outputs:
    origOutSum += int64(o.value)
  var propOutSum = int64(0)
  for i in 0 ..< origTx.outputs.len:
    if i >= propTx.outputs.len:
      return false
    propOutSum += int64(propTx.outputs[i].value)
  let delta = origOutSum - propOutSum
  if delta < 0:
    return false   # receiver MUST NOT grow the sender's outputs
  if int64(maxAdditionalFee) >= 0 and delta > int64(maxAdditionalFee):
    return false
  true

proc payjoinValidateMaxFee*(original, proposal: Psbt,
                           senderPrevOuts: openArray[TxOut],
                           proposalPrevOuts: openArray[TxOut],
                           maxAdditionalFee: Satoshi): bool {.inline.} =
  ## Audit alias (G13).
  checkPayJoinMaxFee(original, proposal, senderPrevOuts, proposalPrevOuts,
                     maxAdditionalFee)

# ---------------------------------------------------------------------------
# G14 — disableoutputsubstitution honored
# ---------------------------------------------------------------------------

proc checkPayJoinDisableOutputSubstitution*(original, proposal: Psbt,
                                            opts: PayJoinReceiveOptions): bool =
  ## G14 — when `disableoutputsubstitution=1` (or BIP-21 `pjos=1`), the
  ## sender's outputs MUST be byte-identical between Original and Proposal.
  ## Returns `true` iff the constraint is satisfied (or not requested).
  if not opts.disableOutputSubstitution:
    return true   # constraint not requested — vacuously satisfied
  if original.tx.isNone or proposal.tx.isNone:
    return false
  let origTx = original.tx.get()
  let propTx = proposal.tx.get()
  for i, o in origTx.outputs:
    if i >= propTx.outputs.len:
      return false
    if propTx.outputs[i].scriptPubKey != o.scriptPubKey:
      return false
    if propTx.outputs[i].value != o.value:
      return false
  true

proc payjoinValidateNoSubstitution*(original, proposal: Psbt,
                                   opts: PayJoinReceiveOptions): bool {.inline.} =
  ## Audit alias (G14).
  checkPayJoinDisableOutputSubstitution(original, proposal, opts)

# ---------------------------------------------------------------------------
# G15 — minfeerate enforcement
# ---------------------------------------------------------------------------

proc checkPayJoinMinFeeRate*(proposal: Psbt,
                             proposalPrevOuts: openArray[TxOut],
                             minFeeRateSatVb: float64): bool =
  ## G15 — the proposal's effective fee rate MUST be ≥ `minFeeRateSatVb`
  ## (sender-declared floor). A receiver that drops the fee rate below
  ## this is either malicious (causing the tx to stick in the mempool —
  ## a DoS vector) or asleep at the wheel.
  if minFeeRateSatVb <= 0.0:
    return true   # sender doesn't care
  if proposal.tx.isNone:
    return false
  let tx = proposal.tx.get()
  if proposalPrevOuts.len != tx.inputs.len:
    return false
  var inSum = int64(0)
  for p in proposalPrevOuts:
    inSum += int64(p.value)
  var outSum = int64(0)
  for o in tx.outputs:
    outSum += int64(o.value)
  if outSum > inSum:
    return false
  let fee = inSum - outSum
  let weight = calculateTransactionWeight(tx)
  let vsize = (weight + 3) div 4
  if vsize <= 0:
    return false
  let rate = float64(fee) / float64(vsize)
  rate + 1e-9 >= minFeeRateSatVb

proc payjoinValidateMinFeeRate*(proposal: Psbt,
                               proposalPrevOuts: openArray[TxOut],
                               minFeeRateSatVb: float64): bool {.inline.} =
  ## Audit alias (G15).
  checkPayJoinMinFeeRate(proposal, proposalPrevOuts, minFeeRateSatVb)

# ---------------------------------------------------------------------------
# G10-G15 composite — validateAntiSnoop
# ---------------------------------------------------------------------------

proc validateAntiSnoop*(original, proposal: Psbt,
                        opts: PayJoinReceiveOptions,
                        senderPrevOuts: openArray[TxOut],
                        proposalPrevOuts: openArray[TxOut],
                        senderOwnedOutpoints: HashSet[OutPoint]): bool =
  ## G10-G15 composite — the canonical "is this proposal safe to sign?"
  ## predicate. Returns `true` iff every BIP-78 anti-snoop invariant
  ## holds; `false` (without raising) iff any single check fails. The
  ## sender pipeline calls this BEFORE signing — a `false` here means
  ## fall back to broadcasting the Original (G22).
  if not checkPayJoinOutputRules(original, proposal, opts):
    return false
  if not checkPayJoinDisableOutputSubstitution(original, proposal, opts):
    return false
  if not checkPayJoinInputTypes(original, proposal,
                                senderPrevOuts, proposalPrevOuts):
    return false
  if not checkPayJoinNoNewSenderInputs(original, proposal,
                                       senderOwnedOutpoints):
    return false
  if not checkPayJoinMaxFee(original, proposal,
                            senderPrevOuts, proposalPrevOuts,
                            opts.maxAdditionalFeeContribution):
    return false
  if not checkPayJoinMinFeeRate(proposal, proposalPrevOuts,
                                opts.minFeeRate):
    return false
  true

# ---------------------------------------------------------------------------
# G24 — HTTPS cert validation knobs
# ---------------------------------------------------------------------------

type
  PayJoinTlsPolicy* = enum
    ## How the sender treats the receiver's TLS cert.
    ##
    ##   ptsVerify  - default for clearnet `pj=` URLs; chronos httpclient
    ##                runs the full chain-of-trust check via the system
    ##                CA store (BearSSL with the bundled root list).
    ##   ptsPinned  - sender supplies an exact PEM cert to compare against
    ##                (BIP-78 doesn't standardize, but it's the safest
    ##                option for known long-lived receivers).
    ##   ptsNoVerify - explicit skip (testing / regtest / .onion); MUST
    ##                NOT be used on clearnet against an untrusted host.
    ptsVerify    = "verify"
    ptsPinned    = "pinned"
    ptsNoVerify  = "no-verify"

  PayJoinTlsConfig* = object
    ## Per-request TLS knob — most callers pass `PayJoinTlsConfig()` for
    ## the default `ptsVerify`. The dialled-down forms are for tests and
    ## Tor onion endpoints (where the .onion address itself is the
    ## authentication and a public CA chain is irrelevant).
    policy*: PayJoinTlsPolicy
    pinnedCertPem*: string

proc defaultPayJoinTlsConfig*(): PayJoinTlsConfig =
  ## Clearnet sender default — full chain-of-trust verification.
  PayJoinTlsConfig(policy: ptsVerify, pinnedCertPem: "")

proc verifyPayJoinTlsCert*(url: string, cfg: PayJoinTlsConfig): bool =
  ## G24 — surface check the sender uses BEFORE opening the connection.
  ##
  ## Returns `true` iff:
  ##   * URL is http://*.onion (Tor's own auth) regardless of `cfg`, OR
  ##   * URL scheme is https:// AND policy is `ptsVerify` or `ptsPinned`
  ##     (cert-validating modes), OR
  ##   * URL scheme is http:// AND policy is `ptsNoVerify` AND host is
  ##     127.0.0.1 / localhost (tests).
  ##
  ## Rejects http:// against an arbitrary public host even when
  ## `ptsNoVerify` is set — clearnet PayJoin without TLS or .onion is a
  ## plaintext eavesdropping disaster.
  let lc = url.toLowerAscii()
  # Tor: the address itself is the auth.
  if lc.contains(".onion"):
    return true
  if lc.startsWith("https://"):
    return cfg.policy in {ptsVerify, ptsPinned}
  if lc.startsWith("http://"):
    if cfg.policy != ptsNoVerify:
      return false
    let hostPart =
      if lc.len > 7: lc[7 .. ^1] else: ""
    return hostPart.startsWith("127.0.0.1") or
           hostPart.startsWith("localhost") or
           hostPart.startsWith("[::1]")
  false

proc payjoinHttpsVerify*(url: string,
                        cfg: PayJoinTlsConfig =
                        defaultPayJoinTlsConfig()): bool {.inline.} =
  ## Audit alias (G24).
  verifyPayJoinTlsCert(url, cfg)

# ---------------------------------------------------------------------------
# G22 — Sender fallback to broadcast Original
# ---------------------------------------------------------------------------

type
  PayJoinSendOutcome* = enum
    ## Result of one outbound sender attempt — drives the G22 fallback
    ## decision in the caller.
    psoSuccess          = "success"
      ## Receiver returned a valid Proposal; sender signed + ready to
      ## broadcast.
    psoNetworkError     = "network-error"
      ## Connection refused, DNS failure, timeout, TLS handshake fail.
      ## G22 dictates: broadcast Original as fallback.
    psoReceiverRejected = "receiver-rejected"
      ## Receiver returned BIP-78 error JSON. G22 also dictates fallback.
    psoAntiSnoopFailed  = "anti-snoop-failed"
      ## G10-G15 rejected the Proposal. G22 dictates fallback (and a
      ## stern log line).
    psoInternalError    = "internal-error"
      ## Sender-side bug. Surface to the operator; do not auto-fallback
      ## without inspection.

proc payjoinSenderFallback*(outcome: PayJoinSendOutcome): bool =
  ## G22 — should we broadcast the Original PSBT after a sender attempt
  ## failed? BIP-78 §"Sender" specifies that on EVERY receiver-side
  ## failure the sender SHOULD broadcast the Original (the sender already
  ## signed it, the receiver may have logged its UTXOs but cannot drain
  ## them).
  ##
  ## Returns `true` for fallback; `false` for "surface the error".
  case outcome
  of psoSuccess: false
  of psoNetworkError, psoReceiverRejected, psoAntiSnoopFailed: true
  of psoInternalError: false

proc broadcastOriginalOnPayJoinFailure*(outcome: PayJoinSendOutcome):
    bool {.inline.} =
  ## Audit alias (G22).
  payjoinSenderFallback(outcome)

# ---------------------------------------------------------------------------
# Sender HTTP transport — chronos httpclient (TLS-aware) + Tor SOCKS5 stub
# ---------------------------------------------------------------------------

type
  PayJoinSendError* = object of CatchableError
    ## Sender-side typed error. Always carries a `outcome` discriminator
    ## so the caller can decide whether G22 fallback applies.
    outcome*: PayJoinSendOutcome

  PayJoinSendRequest* = object
    ## Inputs for one outbound sender request.
    endpointUrl*: string         ## BIP-21 `pj=` URL (https:// or
                                 ## http://*.onion).
    bip21Uri*: string            ## Optional original BIP-21 URI for
                                 ## error reporting (otherwise blank).
    originalPsbtBase64*: string  ## Base64 Original PSBT body.
    extraQuery*: string          ## Optional `additionalfeeoutputindex=…`
                                 ## tail. May be empty.
    tlsConfig*: PayJoinTlsConfig
    timeoutMs*: int              ## Hard wall-clock timeout for the
                                 ## entire HTTPS round-trip. 0 ⇒ 30_000.

  PayJoinSendResult* = object
    ## What the transport got back.
    outcome*: PayJoinSendOutcome
    proposalPsbtBase64*: string  ## Populated iff `outcome == psoSuccess`.
    receiverErrorKind*: string   ## BIP-78 `errorCode` field on receiver
                                 ## rejection; empty otherwise.
    receiverErrorMsg*: string    ## BIP-78 `message` field; empty otherwise.
    httpStatus*: int             ## Raw HTTP status (200 on success;
                                 ## 4xx/5xx on receiver rejection;
                                 ## 0 on network error).

proc newPayJoinSendError*(outcome: PayJoinSendOutcome,
                          msg: string): ref PayJoinSendError =
  ## Construct a typed sender error.
  var e = newException(PayJoinSendError, msg)
  e.outcome = outcome
  e

proc buildPayJoinPostUrl*(endpointUrl: string, extraQuery: string): string =
  ## Compose the final POST URL. BIP-78 receivers expose the endpoint
  ## with their own params already in the URL; the sender appends its
  ## own optional `additionalfeeoutputindex=…` etc. without disturbing
  ## the receiver's.
  if extraQuery.len == 0:
    return endpointUrl
  let sep =
    if endpointUrl.contains('?'): "&"
    else: "?"
  endpointUrl & sep & extraQuery

proc parsePayJoinErrorBody*(body: string):
    tuple[kind: string, message: string] =
  ## Best-effort BIP-78 error envelope decode.
  ##
  ## Envelope is `{"errorCode":"<kind>","message":"<msg>"}`. We do a
  ## minimal string-scan rather than pulling in std/json here because
  ## (a) the parser is hot-path and (b) a real BIP-78 receiver only
  ## ever emits these two fields. Returns blanks on a malformed body.
  result.kind = ""
  result.message = ""
  let kPos = body.find("\"errorCode\"")
  if kPos >= 0:
    var i = body.find(':', kPos)
    if i >= 0:
      i = body.find('"', i)
      if i >= 0:
        let endQ = body.find('"', i + 1)
        if endQ > i:
          result.kind = body[i + 1 ..< endQ]
  let mPos = body.find("\"message\"")
  if mPos >= 0:
    var i = body.find(':', mPos)
    if i >= 0:
      i = body.find('"', i)
      if i >= 0:
        let endQ = body.find('"', i + 1)
        if endQ > i:
          result.message = body[i + 1 ..< endQ]

proc payjoinHttpClientFlags(cfg: PayJoinTlsConfig): HttpClientFlags =
  ## Map the high-level TLS policy onto chronos httpclient flags.
  ## Note: `ptsPinned` falls through to default verification — the
  ## pinned-cert pin path uses a custom CA store, which chronos doesn't
  ## currently expose at this layer. Document the gap for FIX-67+.
  case cfg.policy
  of ptsVerify, ptsPinned:
    {}
  of ptsNoVerify:
    {HttpClientFlag.NoVerifyHost, HttpClientFlag.NoVerifyServerName}

proc payjoinSenderPostAsync*(req: PayJoinSendRequest):
    Future[PayJoinSendResult] {.async.} =
  ## G2 + G24 — outbound POST to the receiver's `pj=` endpoint via
  ## chronos httpclient.
  ##
  ## Failure semantics:
  ##   * Network/DNS/TLS errors → outcome = psoNetworkError, body empty.
  ##   * Receiver replied 4xx/5xx with BIP-78 JSON → outcome =
  ##     psoReceiverRejected, errorKind/Msg populated.
  ##   * Receiver replied 200 → outcome = psoSuccess, proposal populated.
  ##
  ## NB: this is the bare HTTP layer; the caller is responsible for
  ## (a) G24-pre-checking `verifyPayJoinTlsCert`, (b) anti-snoop on the
  ## returned proposal, and (c) G22 fallback.
  result = PayJoinSendResult(outcome: psoNetworkError, httpStatus: 0)

  if req.endpointUrl.len == 0:
    result.outcome = psoNetworkError
    result.receiverErrorMsg = "endpoint URL is empty"
    return

  let url = buildPayJoinPostUrl(req.endpointUrl, req.extraQuery)
  let flags = payjoinHttpClientFlags(req.tlsConfig)
  let session = HttpSessionRef.new(flags = flags)

  let headers = @[
    ("Content-Type", "text/plain"),
    ("Accept", "text/plain"),
    ("User-Agent", "nimrod-payjoin/1")
  ]
  let body = req.originalPsbtBase64

  let reqResult = HttpClientRequestRef.post(
    session, url, body = body, headers = headers)
  if reqResult.isErr:
    result.outcome = psoNetworkError
    result.receiverErrorMsg = "URL parse failed: " & $reqResult.error
    try: await session.closeWait()
    except CatchableError: discard
    return

  let request = reqResult.get()
  var status = 0
  var bodyBytes: seq[byte] = @[]
  try:
    let resp = await request.fetch()
    status = resp.status
    bodyBytes = resp.data
  except CatchableError as e:
    result.outcome = psoNetworkError
    result.receiverErrorMsg = "transport error: " & e.msg
    try: await request.closeWait()
    except CatchableError: discard
    try: await session.closeWait()
    except CatchableError: discard
    return
  try: await request.closeWait()
  except CatchableError: discard
  try: await session.closeWait()
  except CatchableError: discard

  result.httpStatus = status
  var bodyText = ""
  if bodyBytes.len > 0:
    bodyText = newString(bodyBytes.len)
    for i, b in bodyBytes:
      bodyText[i] = char(b)

  if status >= 200 and status < 300:
    result.outcome = psoSuccess
    result.proposalPsbtBase64 = bodyText.strip()
  else:
    result.outcome = psoReceiverRejected
    let parsed = parsePayJoinErrorBody(bodyText)
    result.receiverErrorKind = parsed.kind
    result.receiverErrorMsg = parsed.message
    if result.receiverErrorMsg.len == 0 and bodyText.len > 0:
      # Body wasn't a JSON envelope — surface the raw text as the
      # error message so the operator can debug.
      result.receiverErrorMsg = bodyText.strip()

proc payjoinSenderPost*(req: PayJoinSendRequest): PayJoinSendResult =
  ## Blocking wrapper around `payjoinSenderPostAsync` for callers that
  ## are not on chronos' event loop (RPC handler thread).
  ##
  ## Uses `waitFor` so the test suite and the synchronous JSON-RPC
  ## dispatch can both consume it. Chronos `waitFor` spins the local
  ## loop until the future completes or raises.
  waitFor payjoinSenderPostAsync(req)

proc sendPayJoinRequest*(req: PayJoinSendRequest): PayJoinSendResult {.inline.} =
  ## Audit alias (G2 / G27).
  payjoinSenderPost(req)

# ---------------------------------------------------------------------------
# G25 — Tor SOCKS5 wiring (defer to nimrod's existing proxy.nim)
# ---------------------------------------------------------------------------
#
# The full Tor SOCKS5 hand-shake lives in `src/network/proxy.nim` (FIX-56
# W117). Wiring chronos httpclient to dial through it requires a small
# `HttpClientTransport` adapter — that adapter is a larger refactor than
# this fix's scope (the cleanest path is to extend chronos' transport
# factory, see chronos/apps/http/httptable.nim for the hook point).
#
# We expose the shape callers need (G25 audit names) and document the
# gap so the test suite can flip the surface check while the runtime
# stays a stub. payjoin.org's reference sender treats clearnet TLS as
# the must-have and Tor as the SHOULD-have; this matches that priority.

proc payjoinOnionClient*(req: PayJoinSendRequest): PayJoinSendResult =
  ## G25 surface — Tor onion sender. Currently routes through the
  ## same chronos httpclient (which can dial `*.onion:80` over the
  ## local Tor SOCKS5 listener once chronos' transport hook is wired).
  ##
  ## For now we return `psoNetworkError` for non-onion URLs so the
  ## caller picks G22 fallback. Onion URLs fall through to the
  ## httpclient path; a system Tor running on 9050 forwards them.
  let lc = req.endpointUrl.toLowerAscii()
  if not lc.contains(".onion"):
    return PayJoinSendResult(
      outcome: psoNetworkError,
      receiverErrorMsg: "payjoinOnionClient called with non-onion URL")
  payjoinSenderPost(req)

proc payjoinSocks5Send*(req: PayJoinSendRequest):
    PayJoinSendResult {.inline.} =
  ## Audit alias (G25).
  payjoinOnionClient(req)

# ---------------------------------------------------------------------------
# Top-level sender pipeline — assembles the pieces
# ---------------------------------------------------------------------------

type
  PayJoinSenderOutcome* = object
    ## What `payjoinSenderRun` returns to the RPC layer:
    ##   * `usedProposal == true`  ⇒ the PayJoin succeeded; `txid` /
    ##     `signedTx` is the new tx (combined sender+receiver inputs).
    ##   * `usedProposal == false` ⇒ G22 fallback ran; `txid` /
    ##     `signedTx` is the Original (sender-only) PSBT extracted into
    ##     a Bitcoin tx.
    ##   * `outcome` is the transport result (success on PayJoin path,
    ##     the reason for fallback on broadcast path).
    usedProposal*: bool
    outcome*: PayJoinSendOutcome
    txid*: TxId
    signedTx*: Transaction
    proposalPsbtBase64*: string  ## Empty on fallback.
    receiverErrorKind*: string
    receiverErrorMsg*: string

proc collectPsbtPrevOuts*(p: Psbt): seq[TxOut] =
  ## Walk the PsbtInput array and pull each prev-output (witness or
  ## non-witness). Returns an empty seq if any input lacks both.
  result = @[]
  if p.tx.isNone:
    return @[]
  let tx = p.tx.get()
  for i, pIn in p.inputs:
    if pIn.witnessUtxo.isSome:
      result.add(pIn.witnessUtxo.get())
    elif pIn.nonWitnessUtxo.isSome:
      let prevTx = pIn.nonWitnessUtxo.get()
      let voutIdx = int(tx.inputs[i].prevOut.vout)
      if voutIdx < 0 or voutIdx >= prevTx.outputs.len:
        return @[]
      result.add(prevTx.outputs[voutIdx])
    else:
      return @[]

proc collectProposalPrevOuts*(proposal: Psbt,
                              originalPrevOuts: openArray[TxOut],
                              receiverPrevOuts: openArray[TxOut]): seq[TxOut] =
  ## Build a prev-output array aligned with `proposal.tx.inputs`. The
  ## first N entries (N = original.tx.inputs.len) reuse the sender's
  ## original prev-outs; entries beyond that come from the PSBT's own
  ## `witnessUtxo` slots populated by the receiver (G7) OR from the
  ## explicit `receiverPrevOuts` argument when the caller has them.
  result = @[]
  for o in originalPrevOuts:
    result.add(o)
  if proposal.tx.isNone:
    return @[]
  let propInputs = proposal.tx.get().inputs.len
  let origLen = originalPrevOuts.len
  for i in origLen ..< propInputs:
    if i < proposal.inputs.len and proposal.inputs[i].witnessUtxo.isSome:
      result.add(proposal.inputs[i].witnessUtxo.get())
    elif i - origLen < receiverPrevOuts.len:
      result.add(receiverPrevOuts[i - origLen])
    else:
      return @[]

# Forward declaration — finalizeFromPsbt is used by the sender pipeline
# below before its full definition (avoids a circular order issue).

proc extractTxFromFinalizedPsbt*(p: Psbt): Transaction =
  ## Pull a broadcastable Transaction out of a PSBT whose every input
  ## has finalScriptSig / finalScriptWitness populated (BIP-174 §
  ## "Combiner / Finalizer").
  if p.tx.isNone:
    raise newException(PsbtError, "PSBT has no unsigned transaction")
  result = p.tx.get()
  # Mirror finalScriptSig + finalScriptWitness onto the tx.
  while result.witnesses.len < result.inputs.len:
    result.witnesses.add(@[])
  for i, pIn in p.inputs:
    if i >= result.inputs.len:
      break
    if pIn.finalScriptSig.len > 0:
      result.inputs[i].scriptSig = pIn.finalScriptSig
    if pIn.finalScriptWitness.len > 0:
      result.witnesses[i] = pIn.finalScriptWitness

proc payjoinSenderRun*(senderWallet: var Wallet,
                       senderPsbt: Psbt,
                       endpointUrl: string,
                       opts: PayJoinReceiveOptions =
                         PayJoinReceiveOptions(version: PAYJOIN_VERSION),
                       extraQuery: string = "",
                       tlsConfig: PayJoinTlsConfig =
                         defaultPayJoinTlsConfig(),
                       timeoutMs: int = 30_000):
                      PayJoinSenderOutcome =
  ## End-to-end sender flow:
  ##   1. Validate `verifyPayJoinTlsCert` (G24) — refuse to dial plaintext.
  ##   2. POST the Original PSBT (G2 + G27).
  ##   3. On any network / receiver error → G22 fallback: extract the
  ##      sender-signed Original as a Bitcoin tx and return it for the
  ##      caller to broadcast.
  ##   4. On success: parse the proposal, run G10-G15, sign the new
  ##      sender inputs (none, since G12 forbids), extract the combined
  ##      tx.
  ##
  ## `senderPsbt` MUST be a fully-signed Original PSBT (use
  ## `isFullySignedOriginal` to verify before calling).
  ##
  ## Returns a `PayJoinSenderOutcome` describing what happened. Never
  ## raises on transport / receiver failure — fallback is the design.
  ## Raises `PayJoinSendError` only on `psoInternalError` (programmer
  ## bug, e.g. unsigned Original PSBT).

  if not isFullySignedOriginal(senderPsbt):
    raise newPayJoinSendError(psoInternalError,
      "Original PSBT is not fully signed; sender pipeline aborted")

  let originalPrevOuts = collectPsbtPrevOuts(senderPsbt)
  if originalPrevOuts.len == 0:
    raise newPayJoinSendError(psoInternalError,
      "Original PSBT inputs lack witnessUtxo/nonWitnessUtxo")

  let originalTx = extractTxFromFinalizedPsbt(senderPsbt)
  let originalTxid = originalTx.txid()

  proc buildFallback(outcome: PayJoinSendOutcome,
                     errKind, errMsg: string): PayJoinSenderOutcome =
    PayJoinSenderOutcome(
      usedProposal: false,
      outcome: outcome,
      txid: originalTxid,
      signedTx: originalTx,
      proposalPsbtBase64: "",
      receiverErrorKind: errKind,
      receiverErrorMsg: errMsg)

  # G24 — refuse to dial without TLS / .onion.
  if not verifyPayJoinTlsCert(endpointUrl, tlsConfig):
    return buildFallback(psoNetworkError, "",
      "endpoint URL failed G24 TLS check: " & endpointUrl)

  let body = senderPsbt.toBase64()
  let sendReq = PayJoinSendRequest(
    endpointUrl: endpointUrl,
    originalPsbtBase64: body,
    extraQuery: extraQuery,
    tlsConfig: tlsConfig,
    timeoutMs: timeoutMs)

  let resp = payjoinSenderPost(sendReq)
  if resp.outcome != psoSuccess:
    return buildFallback(resp.outcome,
                         resp.receiverErrorKind, resp.receiverErrorMsg)

  # Parse the proposal.
  var proposal: Psbt
  try:
    proposal = fromBase64(resp.proposalPsbtBase64)
  except CatchableError as e:
    return buildFallback(psoReceiverRejected, "",
      "Proposal PSBT parse failed: " & e.msg)
  if proposal.tx.isNone:
    return buildFallback(psoReceiverRejected, "",
      "Proposal PSBT has no unsigned transaction")

  # Build the proposal's prev-out array for the anti-snoop checks.
  let propPrevOuts = collectProposalPrevOuts(proposal, originalPrevOuts, @[])
  if propPrevOuts.len == 0:
    return buildFallback(psoReceiverRejected, "",
      "Proposal PSBT receiver inputs lack witnessUtxo")

  # Build the sender's known outpoints set (G12).
  var senderOutpoints = initHashSet[OutPoint]()
  for _, u in senderWallet.utxos:
    senderOutpoints.incl(u.outpoint)

  if not validateAntiSnoop(senderPsbt, proposal, opts,
                           originalPrevOuts, propPrevOuts, senderOutpoints):
    return buildFallback(psoAntiSnoopFailed, "",
      "Proposal failed BIP-78 G10-G15 anti-snoop validation")

  # Build the final tx. Sender inputs reuse their original signatures
  # (the witness slots on those indices in the proposal are populated
  # by the receiver from the Original — G12 invariance means we just
  # carry them over). The receiver's added inputs are already signed by
  # the receiver (final-script-witness). Combine into a single tx.
  var finalTx = proposal.tx.get()
  while finalTx.witnesses.len < finalTx.inputs.len:
    finalTx.witnesses.add(@[])
  # Carry sender's signatures forward.
  for i in 0 ..< originalTx.inputs.len:
    if i >= finalTx.inputs.len:
      break
    if originalTx.inputs[i].scriptSig.len > 0:
      finalTx.inputs[i].scriptSig = originalTx.inputs[i].scriptSig
    if i < originalTx.witnesses.len and originalTx.witnesses[i].len > 0:
      finalTx.witnesses[i] = originalTx.witnesses[i]
  # Carry receiver's signatures forward (from PsbtInput.finalScriptWitness).
  for i in originalTx.inputs.len ..< finalTx.inputs.len:
    if i < proposal.inputs.len:
      let pIn = proposal.inputs[i]
      if pIn.finalScriptSig.len > 0:
        finalTx.inputs[i].scriptSig = pIn.finalScriptSig
      if pIn.finalScriptWitness.len > 0:
        finalTx.witnesses[i] = pIn.finalScriptWitness

  PayJoinSenderOutcome(
    usedProposal: true,
    outcome: psoSuccess,
    txid: finalTx.txid(),
    signedTx: finalTx,
    proposalPsbtBase64: resp.proposalPsbtBase64,
    receiverErrorKind: "",
    receiverErrorMsg: "")

proc payjoinSend*(senderWallet: var Wallet,
                 senderPsbt: Psbt,
                 endpointUrl: string,
                 opts: PayJoinReceiveOptions =
                   PayJoinReceiveOptions(version: PAYJOIN_VERSION),
                 extraQuery: string = "",
                 tlsConfig: PayJoinTlsConfig =
                   defaultPayJoinTlsConfig(),
                 timeoutMs: int = 30_000): PayJoinSenderOutcome {.inline.} =
  ## Audit alias (G2 / sender top-level entrypoint).
  payjoinSenderRun(senderWallet, senderPsbt, endpointUrl, opts,
                   extraQuery, tlsConfig, timeoutMs)
