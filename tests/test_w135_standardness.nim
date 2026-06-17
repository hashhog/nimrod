## W135 — Standardness rules (IsStandardTx) audit tests
##
## Discovery-only audit (NO production code change in W135).  These tests
## PIN the CURRENT (potentially divergent) behavior of nimrod's
## `IsStandardTx` / `IsWitnessStandard` / `classifyStdTxout` /
## `dustThreshold` against the audit matrix in `audit/w135_standardness_rules.md`.
##
## When fix waves land, the polarity of the BUG-tagged tests will flip
## from "asserts the divergent behavior" to "asserts the Core-aligned
## behavior" — at that point these become forward-regression guards.
##
## BUG-01 (P0-CDIV): dustThreshold mis-detects v1+ witness programs
## BUG-02 (P0-CDIV): classifyStdTxout has no stxAnchor variant
## BUG-03 (P1):       BIP-54 legacy-sigop cap MAX_TX_LEGACY_SIGOPS=2500 absent
## BUG-04 (P1):       v0 malformed-prog routes to WitnessUnknown, not NonStandard
## BUG-05 (P1):       n=4..16 bare multisig reason-string drift
## BUG-09 (P2):       dustThreshold ignores MAX_SCRIPT_SIZE IsUnspendable branch
## BUG-10 (P3):       outputSize varint hardcoded 1 byte
## BUG-11 (P3):       duplicate dust impls in standard.nim and mempool.nim
## BUG-14 (P3):       docstring drift on "multi-op-return" reason string

import unittest2
import std/options
import ../src/mempool/standard
import ../src/mempool/mempool as mp
import ../src/primitives/[types, serialize]
import ../src/script/interpreter

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

proc p2pkhSpk(): seq[byte] =
  @[byte(OP_DUP), OP_HASH160, 0x14] &
    @(default(array[20, byte])) &
    @[byte(OP_EQUALVERIFY), OP_CHECKSIG]

proc p2shSpk(): seq[byte] =
  @[byte(OP_HASH160), 0x14] & @(default(array[20, byte])) & @[byte(OP_EQUAL)]

proc p2wpkhSpk(): seq[byte] =
  @[byte(OP_0), 0x14] & @(default(array[20, byte]))

proc p2wshSpk(): seq[byte] =
  @[byte(OP_0), 0x20] & @(default(array[32, byte]))

proc p2trSpk(): seq[byte] =
  @[byte(OP_1), 0x20] & @(default(array[32, byte]))

proc p2aSpk(): seq[byte] =
  ## BIP-431 Pay-to-Anchor: OP_1 PUSHBYTES_2 0x4e73
  @[0x51'u8, 0x02, 0x4e, 0x73]

proc p2pkSpk(): seq[byte] =
  ## 33-byte compressed pubkey + OP_CHECKSIG
  var script = @[byte(33)]
  for _ in 0 ..< 33: script.add(0x02'u8)
  script.add(byte(OP_CHECKSIG))
  script

proc opReturnPayload(payload: seq[byte]): seq[byte] =
  result.add(byte(OP_RETURN))
  if payload.len < 0x4c:
    result.add(byte(payload.len))
  else:
    result.add(0x4c'u8)
    result.add(byte(payload.len))
  for b in payload: result.add(b)

proc baseTx(): Transaction =
  Transaction(
    version: 2,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
      scriptSig: @[byte(0x00)],
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(100_000),
      scriptPubKey: p2pkhSpk()
    )],
    witnesses: @[],
    lockTime: 0
  )

# ---------------------------------------------------------------------------
# G20-G23 — Dust threshold formulas across all 5 standard shapes.
# Pins the BUG-01 divergence (v1+ witness program mis-detection).
# ---------------------------------------------------------------------------

suite "W135 — Dust threshold by output shape":

  test "G20 P2PKH dust threshold == 546 sats (Core parity)":
    ## (8 + 25 + 1) + (32+4+1+107+4) = 34 + 148 = 182 → 182*3000/1000 = 546
    let txout = TxOut(value: Satoshi(0), scriptPubKey: p2pkhSpk())
    let t = dustThreshold(txout)
    check int64(t) == 546

  test "G20 P2SH dust threshold == 540 sats (Core parity)":
    ## P2SH script is 23 bytes: 8 + 23 + 1 = 32 outputSize + 148 = 180 → 540
    let txout = TxOut(value: Satoshi(0), scriptPubKey: p2shSpk())
    let t = dustThreshold(txout)
    check int64(t) == 540

  test "G21 P2WPKH dust threshold == 294 sats (Core parity)":
    ## P2WPKH script is 22 bytes; witness program path activates because
    ## script[0]==OP_0==0x00 satisfies the (incorrect-but-coincidentally-right
    ## for v0) byte-pattern check.  outputSize=31, inputSize=67, total=98 → 294.
    let txout = TxOut(value: Satoshi(0), scriptPubKey: p2wpkhSpk())
    let t = dustThreshold(txout)
    check int64(t) == 294

  test "G21 P2WSH dust threshold == 330 sats (Core parity)":
    ## P2WSH script is 34 bytes; witness path: 43 + 67 = 110 → 330.
    let txout = TxOut(value: Satoshi(0), scriptPubKey: p2wshSpk())
    let t = dustThreshold(txout)
    check int64(t) == 330

  test "G22 [BUG-01 FIXED] P2TR dust threshold == 330 sats (Core parity)":
    ## CORE: P2TR is a witness program → witness-discounted input → 330 sats.
    ## Regression guard for the BUG-01 fix: the previous witness test only
    ## matched version bytes 0x00..0x10, so P2TR (script[0] = OP_1 = 0x51) fell
    ## through to the legacy 148-byte input estimate and returned 573. The
    ## Core-faithful isWitnessProgram handles OP_1..OP_16, so 330 is computed.
    ## Mirror of getDustThreshold to keep both impls in lock-step.
    let txout = TxOut(value: Satoshi(0), scriptPubKey: p2trSpk())
    check int64(dustThreshold(txout)) == 330'i64
    check int64(mp.getDustThreshold(txout)) == 330'i64

  test "G22 [BUG-01 FIXED] WitnessUnknown v2 dust threshold uses witness input estimate":
    ## A 4-byte v2 program: [OP_2, 0x02, 0xAA, 0xBB].  Core: witness program,
    ## input cost 67, nSize = (8+1+4) + 67 = 80, threshold = 240. Pre-fix nimrod
    ## mis-classified it (script[0]=0x52, NOT <= 0x10) → legacy 148 → 483.
    let txout = TxOut(
      value: Satoshi(0),
      scriptPubKey: @[byte(OP_2), 0x02'u8, 0xAA'u8, 0xBB'u8]
    )
    check int64(dustThreshold(txout)) == 240'i64
    check int64(mp.getDustThreshold(txout)) == 240'i64

  test "G23 OP_RETURN dust threshold == 0 (Core parity)":
    let txout = TxOut(
      value: Satoshi(0),
      scriptPubKey: @[byte(OP_RETURN), 0x01'u8, 0x42'u8]
    )
    check int64(dustThreshold(txout)) == 0

# ---------------------------------------------------------------------------
# G19 — Ephemeral dust allowance (MAX_DUST_OUTPUTS_PER_TX = 1)
# ---------------------------------------------------------------------------

suite "W135 — Ephemeral dust allowance":

  test "G19 single dust output accepted (1 ≤ MAX_DUST_OUTPUTS_PER_TX)":
    var tx = baseTx()
    tx.outputs[0].value = Satoshi(1)  # well under 546
    let r = isStandardTx(tx)
    check r.ok

  test "G19 two dust outputs rejected as 'dust'":
    var tx = baseTx()
    tx.outputs = @[
      TxOut(value: Satoshi(1), scriptPubKey: p2pkhSpk()),
      TxOut(value: Satoshi(1), scriptPubKey: p2pkhSpk())
    ]
    let r = isStandardTx(tx)
    check not r.ok
    check r.reason == "dust"

# ---------------------------------------------------------------------------
# G10 / G31 — Pay-to-Anchor classification (BUG-02 PIN)
# ---------------------------------------------------------------------------

suite "W135 — Pay-to-Anchor classification [BUG-02]":

  test "[BUG-02 PIN] classifyStdTxout(P2A) returns stxWitnessUnknown (Core: ANCHOR)":
    ## Core's Solver returns TxoutType::ANCHOR for [OP_1, 0x02, 0x4e, 0x73].
    ## Nimrod has no stxAnchor variant, so it falls through to stxWitnessUnknown.
    ## When BUG-02 is fixed, add stxAnchor and flip this check.
    let kind = classifyStdTxout(p2aSpk())
    check kind == stxWitnessUnknown
    # The output-side "is standard?" test passes coincidentally because
    # stxWitnessUnknown is in the `else: discard` branch (not rejected):
    var tx = baseTx()
    tx.outputs[0] = TxOut(value: Satoshi(330), scriptPubKey: p2aSpk())
    let r = isStandardTx(tx)
    check r.ok

  test "[BUG-02 docs] P2A is recognized by the isP2A predicate":
    ## isP2A() correctly identifies P2A; it's only the dispatch
    ## inside classifyStdTxout that mis-routes.
    check isP2A(p2aSpk())
    check not isP2A(p2trSpk())     # 32-byte P2TR is not anchor
    check not isP2A(p2wpkhSpk())   # v0 keyhash is not anchor

# ---------------------------------------------------------------------------
# G11 / G31 — v0 malformed-program dispatch (BUG-04 PIN)
# ---------------------------------------------------------------------------

suite "W135 — v0 malformed witness-program classification [BUG-04]":

  test "[BUG-04 PIN] v0 with prog.len=5 → stxWitnessUnknown (Core: NONSTANDARD)":
    ## Script: [OP_0, 0x05, 0, 1, 2, 3, 4].  Core's Solver returns NONSTANDARD
    ## for v0 with prog.len ∉ {20, 32}.  Nimrod's classifyStdTxout returns
    ## stxWitnessUnknown (line 175).  Output-side: nimrod ACCEPTS, Core REJECTS.
    let script = @[byte(OP_0), 0x05'u8, 0'u8, 1'u8, 2'u8, 3'u8, 4'u8]
    let kind = classifyStdTxout(script)
    check kind == stxWitnessUnknown  # nimrod current — pin
    var tx = baseTx()
    tx.outputs[0] = TxOut(value: Satoshi(10_000), scriptPubKey: script)
    let r = isStandardTx(tx)
    # Output side: nimrod accepts (stxWitnessUnknown is not rejected at output)
    check r.ok

  test "[BUG-04 PIN] v0 with prog.len=15 → stxWitnessUnknown (Core: NONSTANDARD)":
    var script = @[byte(OP_0), 0x0F'u8]  # OP_0 + push-15-bytes
    for _ in 0 ..< 15: script.add(0xAA'u8)
    check script.len == 17
    let kind = classifyStdTxout(script)
    check kind == stxWitnessUnknown

  test "v0 with prog.len=20 (P2WPKH) → stxP2WPKH (Core parity ✓)":
    let kind = classifyStdTxout(p2wpkhSpk())
    check kind == stxP2WPKH

  test "v0 with prog.len=32 (P2WSH) → stxP2WSH (Core parity ✓)":
    let kind = classifyStdTxout(p2wshSpk())
    check kind == stxP2WSH

# ---------------------------------------------------------------------------
# G14 / G17 — Bare multisig reason-string drift (BUG-05 PIN)
# ---------------------------------------------------------------------------

suite "W135 — Bare multisig n>3 reason-string [BUG-05]":

  proc bareNofM(m, n: int): seq[byte] =
    ## Build OP_m <33-byte pk> ... (n times) ... OP_n OP_CHECKMULTISIG
    result.add(byte(OP_1 + uint8(m - 1)))
    for keyIdx in 0 ..< n:
      result.add(33'u8)
      for _ in 0 ..< 33: result.add(0x02'u8)
    result.add(byte(OP_1 + uint8(n - 1)))
    result.add(byte(OP_CHECKMULTISIG))

  test "G14 1-of-2 bare multisig (n ≤ 3) — accepted with permitBareMultisig=true":
    var tx = baseTx()
    tx.outputs[0].scriptPubKey = bareNofM(1, 2)
    let r = isStandardTx(tx)
    check r.ok

  test "G14 3-of-3 bare multisig (n == 3) — accepted":
    var tx = baseTx()
    tx.outputs[0].scriptPubKey = bareNofM(3, 3)
    let r = isStandardTx(tx)
    check r.ok

  test "[BUG-05 PIN] 1-of-4 bare multisig: nimrod returns 'bare-multisig' (Core: 'scriptpubkey')":
    ## Core's IsStandard helper returns false at the n>3 check BEFORE the
    ## bare-multisig gate fires, producing reason="scriptpubkey".  Nimrod
    ## treats the n>3 check INSIDE the multisig branch and returns
    ## "bare-multisig" instead.  Real reason-string divergence.
    var tx = baseTx()
    tx.outputs[0].scriptPubKey = bareNofM(1, 4)
    let r = isStandardTx(tx)
    check not r.ok
    # Pin current nimrod behavior (the BUG):
    check r.reason == "bare-multisig"
    # When BUG-05 is fixed, this should be "scriptpubkey":
    let coreExpected = "scriptpubkey"
    check r.reason != coreExpected

  test "[BUG-05 partial] 17-of-N multisig (encoded via OP_n): classified stxNonStandard":
    ## Pushdata-encoded m/n (needed for n=17..20) is not supported by
    ## nimrod's isStandardMultisig (line 130 rejects nOp > OP_16).  This
    ## means a 1-of-17 multisig is classified stxNonStandard, with reason
    ## "scriptpubkey" — coincidentally matching Core's reason (Core also
    ## returns "scriptpubkey" because IsStandard rejects n>3).
    var script = @[byte(OP_1)]                          # m=1
    for keyIdx in 0 ..< 17:
      script.add(33'u8)
      for _ in 0 ..< 33: script.add(0x02'u8)
    # n=17 must be pushdata-encoded; nimrod's parser only looks at the
    # second-to-last byte as nOp and expects OP_1..OP_16.  We use a 1-byte
    # push of integer 17 (which Core's GetScriptNumber would accept after
    # CheckMinimalPush — though minimal push of 17 IS valid, since OP_17
    # doesn't exist).
    script.add(0x01'u8)  # PUSHBYTES_1
    script.add(17'u8)
    script.add(byte(OP_CHECKMULTISIG))
    var tx = baseTx()
    tx.outputs[0].scriptPubKey = script
    let r = isStandardTx(tx)
    check not r.ok
    check r.reason == "scriptpubkey"   # nimrod ✓ (matches Core by happenstance)

# ---------------------------------------------------------------------------
# G16 — OP_RETURN datacarrier byte-budget (Core parity)
# ---------------------------------------------------------------------------

suite "W135 — Datacarrier bytes-budget":

  test "G16 single OP_RETURN under budget accepted":
    var tx = baseTx()
    tx.outputs[0] = TxOut(
      value: Satoshi(0),
      scriptPubKey: opReturnPayload(@[byte(0x01), 0x02, 0x03])
    )
    check isStandardTx(tx).ok

  test "G16 multiple OP_RETURNs cumulative-bytes (no count limit in 31.99)":
    var tx = baseTx()
    tx.outputs = @[
      TxOut(value: Satoshi(0), scriptPubKey: opReturnPayload(@[byte(0xAA)])),
      TxOut(value: Satoshi(0), scriptPubKey: opReturnPayload(@[byte(0xBB)])),
      TxOut(value: Satoshi(0), scriptPubKey: opReturnPayload(@[byte(0xCC)]))
    ]
    check isStandardTx(tx).ok

  test "G16 OP_RETURN above per-tx budget rejected as 'datacarrier'":
    var tx = baseTx()
    var opts = defaultIsStandardOptions()
    opts.maxDatacarrierBytes = some(40)
    tx.outputs[0] = TxOut(
      value: Satoshi(0),
      scriptPubKey: opReturnPayload(newSeq[byte](80))
    )
    let r = isStandardTx(tx, opts)
    check not r.ok
    check r.reason == "datacarrier"

  test "G16 [BUG-08 PIN] maxDatacarrierBytes=None disables OP_RETURN":
    ## Set maxDatacarrierBytes to None — nimrod must treat as zero-budget.
    var tx = baseTx()
    var opts = defaultIsStandardOptions()
    opts.maxDatacarrierBytes = none(int)
    tx.outputs[0] = TxOut(
      value: Satoshi(0),
      scriptPubKey: opReturnPayload(@[byte(0xAA)])
    )
    let r = isStandardTx(tx, opts)
    check not r.ok
    check r.reason == "datacarrier"
    # NOTE BUG-08: in production this code path is unreachable because
    # mempool.nim:921 always calls isStandardTx(tx) with defaults, never
    # forwarding any CLI override.

# ---------------------------------------------------------------------------
# G24 / G25 / G26 — CLI-flag plumbing surface (BUG-06/07/08 PIN)
# ---------------------------------------------------------------------------

suite "W135 — CLI-flag plumbing for -dustrelayfee / -permitbaremultisig / -datacarrier":

  test "[BUG-06 PIN] dust feerate is hardcoded 3000 sat/kvB in standard.nim":
    ## There is no API to pass a non-default dust_relay_feerate; nimrod's
    ## dustThreshold uses StdDustRelayTxFee = 3000 unconditionally.
    ## Pin by computing the threshold for a P2WPKH output and asserting
    ## the value matches the 3000-sat/kvB formula exactly (which excludes
    ## the possibility of a CLI override).
    let txout = TxOut(value: Satoshi(0), scriptPubKey: p2wpkhSpk())
    check int64(dustThreshold(txout)) == 294
    # If a CLI override were wired, raising -dustrelayfee=10000 would
    # produce threshold = 980.  Since there's no override path, this
    # value is immutable.

  test "[BUG-07 PIN] permitBareMultisig defaults to true; no CLI plumbing":
    let opts = defaultIsStandardOptions()
    check opts.permitBareMultisig == true

  test "[BUG-08 PIN] maxDatacarrierBytes defaults to some(MaxOpReturnRelayBytes)":
    let opts = defaultIsStandardOptions()
    check opts.maxDatacarrierBytes.isSome
    check opts.maxDatacarrierBytes.get() == MaxOpReturnRelayBytes
    check MaxOpReturnRelayBytes == 100_000

# ---------------------------------------------------------------------------
# G30 — BIP-54 legacy sigop cap (BUG-03 PIN — proc absent)
# ---------------------------------------------------------------------------

suite "W135 — BIP-54 MAX_TX_LEGACY_SIGOPS=2500 enforcement [BUG-03]":

  test "[BUG-03 PIN] MaxTxLegacySigops constant absent from consensus params":
    ## Compile-time pin: the constant doesn't exist (would error if uncommented).
    ## We use a runtime substitute: the consensus/params module defines
    ## MaxStandardTxSigopsCost=16000 and MaxBlockSigopsCost=80000 but no
    ## MaxTxLegacySigops.  The audit framework prescribes 2500.
    when declared(MaxTxLegacySigops):
      # If a future fix wave introduces the constant, this branch fires:
      check MaxTxLegacySigops == 2_500
    else:
      # Current state: constant doesn't exist.  Pin the absence.
      check true  # placeholder — the absence IS the test result

  test "[BUG-03 PIN] no `checkSigopsBIP54` proc exists in mempool":
    ## Compile-time pin via `declared` — there is no proc by this name.
    when declared(checkSigopsBIP54):
      check false  # if the proc exists, this test starts failing on purpose
    else:
      check true   # absence confirmed

# ---------------------------------------------------------------------------
# G9 / G15 — IsUnspendable handling in dust path (BUG-09 PIN)
# ---------------------------------------------------------------------------

suite "W135 — IsUnspendable in dust threshold path [BUG-09]":

  test "G9 OP_RETURN-headed script (any size) → dust threshold 0":
    let txout = TxOut(
      value: Satoshi(0),
      scriptPubKey: @[byte(OP_RETURN)] & newSeq[byte](50)  # ignore the
                                                          # truncated-push
                                                          # malformedness
    )
    check int64(dustThreshold(txout)) == 0

  test "[BUG-09 FIXED] non-OP_RETURN script >MAX_SCRIPT_SIZE → dust threshold 0":
    ## Core's IsUnspendable() returns true for size > MAX_SCRIPT_SIZE (10000),
    ## causing GetDustThreshold to return 0. The dust path now delegates the
    ## unspendable check to isUnspendable (which mirrors CScript::IsUnspendable:
    ## OP_RETURN-headed OR size > MAX_SCRIPT_SIZE), so a 10001-byte script gets
    ## threshold 0 like Core. Regression guard for the BUG-09 fix.
    let bigScript = newSeq[byte](10_001)
    let txout = TxOut(value: Satoshi(0), scriptPubKey: bigScript)
    check int64(dustThreshold(txout)) == 0
    check int64(mp.getDustThreshold(txout)) == 0

# ---------------------------------------------------------------------------
# G15 / classification — basic output-shape coverage
# ---------------------------------------------------------------------------

suite "W135 — Output classification — standard shapes":

  test "P2PKH → stxP2PKH":
    check classifyStdTxout(p2pkhSpk()) == stxP2PKH

  test "P2SH → stxP2SH":
    check classifyStdTxout(p2shSpk()) == stxP2SH

  test "P2WPKH → stxP2WPKH":
    check classifyStdTxout(p2wpkhSpk()) == stxP2WPKH

  test "P2WSH → stxP2WSH":
    check classifyStdTxout(p2wshSpk()) == stxP2WSH

  test "P2TR → stxP2TR":
    check classifyStdTxout(p2trSpk()) == stxP2TR

  test "P2PK (compressed) → stxP2PK":
    check classifyStdTxout(p2pkSpk()) == stxP2PK

  test "Empty script → stxNonStandard":
    check classifyStdTxout(@[]) == stxNonStandard

  test "Truncated OP_RETURN push → stxNonStandard (W58-1 regression)":
    let mal = @[byte(0x6a), 0x09, 0xde, 0xad, 0xbe, 0xef]
    check classifyStdTxout(mal) == stxNonStandard

# ---------------------------------------------------------------------------
# G2 — Version-field signed-vs-unsigned semantics (BUG-15 PIN)
# ---------------------------------------------------------------------------

suite "W135 — Version field semantics [BUG-15]":

  test "Version 1, 2, 3 accepted":
    for v in 1 .. 3:
      var tx = baseTx()
      tx.version = int32(v)
      check isStandardTx(tx).ok

  test "Version 0 rejected as 'version'":
    var tx = baseTx()
    tx.version = 0
    let r = isStandardTx(tx)
    check not r.ok
    check r.reason == "version"

  test "Version 4 rejected as 'version' (above TX_MAX_STANDARD_VERSION)":
    var tx = baseTx()
    tx.version = 4
    let r = isStandardTx(tx)
    check not r.ok
    check r.reason == "version"

  test "[BUG-15 PIN] negative version int32 wraps (Core uses uint32_t)":
    ## Nimrod's tx.version is int32.  A wire byte sequence that decodes as
    ## 0x80000001 wraps to negative.  Both nimrod and Core reject as
    ## 'version' (different sign, same outcome).
    var tx = baseTx()
    tx.version = -2_147_483_648'i32  # 0x80000000 reinterpreted as int32
    let r = isStandardTx(tx)
    check not r.ok
    check r.reason == "version"

# ---------------------------------------------------------------------------
# G3 — Weight cap & G27 — MIN_STANDARD_TX_NONWITNESS_SIZE
# ---------------------------------------------------------------------------

suite "W135 — Weight cap and tx-size-small":

  test "G3 huge tx rejected as 'tx-size'":
    var tx = baseTx()
    tx.inputs = @[]
    for i in 0 ..< 410:
      tx.inputs.add(TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: uint32(i)),
        scriptSig: newSeq[byte](1000),
        sequence: 0xFFFFFFFF'u32
      ))
    let r = isStandardTx(tx)
    check not r.ok
    check r.reason == "tx-size"

  test "G27 baseTx non-witness size >= 65 (MIN_STANDARD_TX_NONWITNESS_SIZE)":
    ## Core's PreChecks enforces this; nimrod enforces it in mempool.nim:909
    ## (not in isStandardTx itself).  We assert the structural property here
    ## as documentation.
    let tx = baseTx()
    check serializeLegacy(tx).len >= 65

# ---------------------------------------------------------------------------
# G37 — IsWitnessStandard coinbase exemption
# ---------------------------------------------------------------------------

suite "W135 — IsWitnessStandard coinbase exempt":

  test "G37 coinbase is exempt from IsWitnessStandard":
    let coinbase = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
        scriptSig: @[byte(0x03), 0x01, 0x00, 0x00],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(5_000_000_000),
        scriptPubKey: p2pkhSpk()
      )],
      witnesses: @[],
      lockTime: 0
    )
    let r = isWitnessStandard(coinbase, proc(_: TxIn): seq[byte] = @[])
    check r.ok
