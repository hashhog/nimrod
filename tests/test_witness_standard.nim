## Tests for IsWitnessStandard (mempool/standard.nim)
## Mirrors Bitcoin Core's IsWitnessStandard() from policy/policy.cpp:265-351.
##
## Gate 1 (policy.cpp:283-285):  P2A + any witness → reject
## Gate 2 (policy.cpp:288-299):  P2SH-wrapped: eval scriptSig pushes; top = redeemScript
## Gate 3 (policy.cpp:305-306):  non-witness prevScript + non-empty witness → reject
## Gate 4 (policy.cpp:309-318):  P2WSH v0 32B: script ≤ 3600; stack-1 ≤ 100; each item ≤ 80
## Gate 5 (policy.cpp:324-348):  P2TR v1 32B (not P2SH): annex 0x50 reject; tapscript 0xc0 → item ≤ 80; empty → reject
## Gate 6 (policy.cpp:267-268):  coinbase exempt

import unittest2
import ../src/mempool/standard
import ../src/primitives/[types, serialize]
import ../src/script/interpreter

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

proc p2pkhScript(): seq[byte] =
  @[byte(OP_DUP), OP_HASH160, 0x14] &
    @(default(array[20, byte])) &
    @[byte(OP_EQUALVERIFY), OP_CHECKSIG]

proc p2wpkhScript(): seq[byte] =
  ## OP_0 <20 bytes>
  @[byte(OP_0), 0x14] & @(default(array[20, byte]))

proc p2wshScript(): seq[byte] =
  ## OP_0 <32 bytes>
  @[byte(OP_0), 0x20] & @(default(array[32, byte]))

proc p2trScript(): seq[byte] =
  ## OP_1 <32 bytes>
  @[byte(OP_1), 0x20] & @(default(array[32, byte]))

proc p2shScript(): seq[byte] =
  ## OP_HASH160 <20 bytes> OP_EQUAL
  @[byte(OP_HASH160), 0x14] & @(default(array[20, byte])) & @[byte(OP_EQUAL)]

proc p2aScript(): seq[byte] =
  ## OP_1 PUSHBYTES_2 0x4e73 (Pay-to-Anchor)
  @[0x51'u8, 0x02, 0x4e, 0x73]

proc makeWitness(items: seq[seq[byte]]): seq[seq[seq[byte]]] =
  @[items]

proc dummyTx(prevScript: seq[byte], witness: seq[seq[byte]],
             scriptSig: seq[byte] = @[]): tuple[tx: Transaction, spk: seq[byte]] =
  ## Build a minimal 1-input tx whose UTXO prevScript is returned alongside it.
  let tx = Transaction(
    version: 2,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
      scriptSig: scriptSig,
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(
      value: Satoshi(50_000),
      scriptPubKey: p2pkhScript()
    )],
    witnesses: makeWitness(witness),
    lockTime: 0
  )
  (tx, prevScript)

proc check(prevScript: seq[byte], witness: seq[seq[byte]],
           scriptSig: seq[byte] = @[]): tuple[ok: bool, reason: string] =
  let (tx, spk) = dummyTx(prevScript, witness, scriptSig)
  isWitnessStandard(tx,
    proc(input: TxIn): seq[byte] = spk)

# Convenience: build N identical items of given length
proc items(count: int, itemLen: int): seq[seq[byte]] =
  for _ in 0 ..< count:
    result.add(newSeq[byte](itemLen))

# ---------------------------------------------------------------------------
# Suite: gate 6 — coinbase exempt
# ---------------------------------------------------------------------------

suite "IsWitnessStandard — Gate 6: coinbase exempt":
  test "coinbase tx with P2A witness passes (coinbase exempt)":
    # Gate 6: coinbase is always exempt regardless of witness shape.
    let coinbaseTx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(
          txid: TxId(default(array[32, byte])),
          vout: 0xFFFFFFFF'u32
        ),
        scriptSig: @[byte(0x03), 0x01, 0x00, 0x00],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(5_000_000_000),
        scriptPubKey: p2pkhScript()
      )],
      witnesses: makeWitness(@[newSeq[byte](100)]),
      lockTime: 0
    )
    let r = isWitnessStandard(coinbaseTx,
      proc(input: TxIn): seq[byte] = p2aScript())
    check r.ok

# ---------------------------------------------------------------------------
# Suite: gate 1 — P2A + witness → nonstandard
# ---------------------------------------------------------------------------

suite "IsWitnessStandard — Gate 1: P2A + witness nonstandard":
  test "P2A prevScript + non-empty witness → rejected":
    let r = check(p2aScript(), @[newSeq[byte](20)])
    check not r.ok
    check r.reason == "bad-witness-nonstandard"

  test "P2A prevScript + empty witness → passes (skipped per policy.cpp:274)":
    ## Core skips inputs with IsNull witness (no items). Empty outer list = no witness.
    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(50_000),
        scriptPubKey: p2pkhScript()
      )],
      witnesses: @[],     # No witness data at all → skipped
      lockTime: 0
    )
    let r = isWitnessStandard(tx, proc(input: TxIn): seq[byte] = p2aScript())
    check r.ok

# ---------------------------------------------------------------------------
# Suite: gate 3 — non-witness prevScript + non-empty witness → nonstandard
# ---------------------------------------------------------------------------

suite "IsWitnessStandard — Gate 3: non-witness prevScript + witness rejected":
  test "P2PKH prevScript + witness → rejected":
    let r = check(p2pkhScript(), @[newSeq[byte](10)])
    check not r.ok
    check r.reason == "bad-witness-nonstandard"

  test "P2WPKH prevScript + witness → passes (is a witness program)":
    ## P2WPKH is a witness program so gate 3 passes; no per-item limits for v0-20B.
    let r = check(p2wpkhScript(), @[newSeq[byte](73), newSeq[byte](33)])
    check r.ok

  test "P2WSH prevScript + empty witness (0 items) → passes gate 3 (skipped)":
    ## Empty witness list → input is skipped entirely.
    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(50_000),
        scriptPubKey: p2pkhScript()
      )],
      witnesses: @[@[]],  # 1 input, witness has 0 items
      lockTime: 0
    )
    let r = isWitnessStandard(tx, proc(input: TxIn): seq[byte] = p2pkhScript())
    check r.ok

# ---------------------------------------------------------------------------
# Suite: gate 4 — P2WSH v0 32-byte checks
# ---------------------------------------------------------------------------

suite "IsWitnessStandard — Gate 4: P2WSH limits":
  proc p2wshWitness(scriptLen: int, stackCount: int, itemLen: int): seq[seq[byte]] =
    ## Build a P2WSH witness: stackCount items of itemLen bytes, then witnessScript.
    result = items(stackCount, itemLen)
    result.add(newSeq[byte](scriptLen))  # witnessScript at the end

  test "P2WSH: normal spend (script=100B, 3 items of 32B each) → accepted":
    let r = check(p2wshScript(), p2wshWitness(100, 3, 32))
    check r.ok

  test "P2WSH: witnessScript exactly 3600 bytes → accepted (boundary)":
    let r = check(p2wshScript(), p2wshWitness(3600, 1, 32))
    check r.ok

  test "P2WSH: witnessScript 3601 bytes → rejected":
    let r = check(p2wshScript(), p2wshWitness(3601, 1, 32))
    check not r.ok
    check r.reason == "bad-witness-nonstandard"

  test "P2WSH: exactly 100 stack items (excl. witnessScript) → accepted (boundary)":
    let r = check(p2wshScript(), p2wshWitness(100, 100, 1))
    check r.ok

  test "P2WSH: 101 stack items (excl. witnessScript) → rejected":
    let r = check(p2wshScript(), p2wshWitness(100, 101, 1))
    check not r.ok
    check r.reason == "bad-witness-nonstandard"

  test "P2WSH: stack item exactly 80 bytes → accepted (boundary)":
    let r = check(p2wshScript(), p2wshWitness(100, 1, 80))
    check r.ok

  test "P2WSH: stack item 81 bytes → rejected":
    let r = check(p2wshScript(), p2wshWitness(100, 1, 81))
    check not r.ok
    check r.reason == "bad-witness-nonstandard"

  test "P2WSH: empty witness for P2WSH → skipped (not a gate-4 input)":
    ## An input with no witness items passes (gate-3 loop skips it).
    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(50_000),
        scriptPubKey: p2pkhScript()
      )],
      witnesses: @[@[]],
      lockTime: 0
    )
    let r = isWitnessStandard(tx, proc(input: TxIn): seq[byte] = p2wshScript())
    check r.ok

# ---------------------------------------------------------------------------
# Suite: gate 5 — P2TR v1 32-byte (not P2SH-wrapped)
# ---------------------------------------------------------------------------

suite "IsWitnessStandard — Gate 5: P2TR tapscript limits":
  proc keyPathWitness(): seq[seq[byte]] =
    ## Key-path spend: just a 64-byte Schnorr signature.
    @[newSeq[byte](64)]

  proc taprootControlBlock(leafVersion: uint8 = 0xc0'u8): seq[byte] =
    ## Minimal valid control block: 1 version byte + 32-byte internal key.
    result = @[leafVersion]
    for _ in 0 ..< 32:
      result.add(0x00'u8)

  proc scriptPathWitness(script: seq[byte], cb: seq[byte],
                          stackItems: seq[seq[byte]]): seq[seq[byte]] =
    ## Script-path spend: stack items, then script, then control block.
    result = stackItems
    result.add(script)
    result.add(cb)

  test "P2TR: key-path spend (1 item) → accepted":
    let r = check(p2trScript(), keyPathWitness())
    check r.ok

  test "P2TR: empty witness → rejected (gate 5, 0-item branch)":
    let r = check(p2trScript(), @[])
    ## Note: 0 items → the outer hasWitness check (tx.witnesses[i].len > 0) skips it.
    ## So we need to pass a non-empty witnesses array with 0 items inside.
    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(50_000),
        scriptPubKey: p2pkhScript()
      )],
      witnesses: makeWitness(@[]),  # outer has 1 entry, inner has 0 items
      lockTime: 0
    )
    let r2 = isWitnessStandard(tx, proc(input: TxIn): seq[byte] = p2trScript())
    ## hasWitness = tx.witnesses[0].len > 0 = false → skipped, so it passes.
    check r2.ok

  test "P2TR: annex present (2 items, last starts 0x50) → rejected":
    let annexedWitness = @[
      newSeq[byte](64),          # signature (item 0)
      @[AnnexTag, 0x01'u8]       # annex (item 1, starts with 0x50)
    ]
    let r = check(p2trScript(), annexedWitness)
    check not r.ok
    check r.reason == "bad-witness-nonstandard"

  test "P2TR: script-path tapscript (0xc0) all items ≤ 80B → accepted":
    let cb = taprootControlBlock(0xc0'u8)
    let witness = scriptPathWitness(@[byte(OP_TRUE)], cb,
                    @[newSeq[byte](80), newSeq[byte](80)])
    let r = check(p2trScript(), witness)
    check r.ok

  test "P2TR: script-path tapscript (0xc0) one item 81B → rejected":
    let cb = taprootControlBlock(0xc0'u8)
    let witness = scriptPathWitness(@[byte(OP_TRUE)], cb,
                    @[newSeq[byte](81)])
    let r = check(p2trScript(), witness)
    check not r.ok
    check r.reason == "bad-witness-nonstandard"

  test "P2TR: script-path non-tapscript leaf (0xc2 after mask) → no item-size check":
    ## Leaf version 0xc2: (0xc2 & 0xfe) = 0xc2, not 0xc0 → no item-size gate.
    let cb = taprootControlBlock(0xc2'u8)
    let witness = scriptPathWitness(@[byte(OP_TRUE)], cb,
                    @[newSeq[byte](200)])  # 200B item allowed for non-tapscript leaf
    let r = check(p2trScript(), witness)
    check r.ok

  test "P2TR: script-path with empty control block → rejected":
    let emptyControlBlock: seq[byte] = @[]
    let witness = scriptPathWitness(@[byte(OP_TRUE)], emptyControlBlock,
                    @[newSeq[byte](10)])
    let r = check(p2trScript(), witness)
    check not r.ok
    check r.reason == "bad-witness-nonstandard"

# ---------------------------------------------------------------------------
# Suite: gate 2 — P2SH-wrapped witness programs
# ---------------------------------------------------------------------------

suite "IsWitnessStandard — Gate 2: P2SH-wrapped witness":
  proc p2shWrappedP2WSHScriptSig(): seq[byte] =
    ## scriptSig that pushes a P2WSH redeemScript:
    ## OP_0 <32 bytes>  (34 bytes total)
    let redeemScript: seq[byte] = @[byte(OP_0), 0x20] & @(default(array[32, byte]))
    # Push redeemScript: length byte + data
    result = @[byte(redeemScript.len)]
    result &= redeemScript

  proc p2wshWrappedWitness(): seq[seq[byte]] =
    ## Minimal P2SH(P2WSH) witness: a few small items + witnessScript.
    @[newSeq[byte](32), newSeq[byte](10)]  # item + witnessScript

  test "P2SH(P2WSH): valid scriptSig + normal witness → accepted":
    let r = check(p2shScript(), p2wshWrappedWitness(), p2shWrappedP2WSHScriptSig())
    check r.ok

  test "P2SH: empty scriptSig (no redeemScript) → rejected":
    let r = check(p2shScript(), @[newSeq[byte](10)], @[])
    check not r.ok
    check r.reason == "bad-witness-nonstandard"

  test "P2SH: non-push scriptSig → rejected (eval failure)":
    ## OP_DUP is a non-push opcode — evalScriptSigPushes returns (false, []).
    let r = check(p2shScript(), @[newSeq[byte](10)], @[byte(OP_DUP)])
    check not r.ok
    check r.reason == "bad-witness-nonstandard"

  test "P2SH(P2WPKH): P2SH wrapping P2WPKH is a witness program → accepted":
    ## redeemScript = OP_0 <20 bytes>
    let redeemScript: seq[byte] = @[byte(OP_0), 0x14] & @(default(array[20, byte]))
    var scriptSig: seq[byte] = @[byte(redeemScript.len)]
    scriptSig &= redeemScript
    let witness = @[newSeq[byte](73), newSeq[byte](33)]  # sig + pubkey
    let r = check(p2shScript(), witness, scriptSig)
    check r.ok

  test "P2SH with non-witness redeemScript + witness → rejected (gate 3)":
    ## redeemScript is plain P2PKH — not a witness program.
    ## After extracting it, gate 3 fires: non-witness program + witness = nonstandard.
    let redeemScript = p2pkhScript()
    var scriptSig: seq[byte] = @[byte(redeemScript.len)]
    scriptSig &= redeemScript
    let witness = @[newSeq[byte](10)]
    let r = check(p2shScript(), witness, scriptSig)
    check not r.ok
    check r.reason == "bad-witness-nonstandard"

# ---------------------------------------------------------------------------
# Suite: evalScriptSigPushes unit tests
# ---------------------------------------------------------------------------

suite "evalScriptSigPushes helper":
  test "empty scriptSig → empty stack":
    let (ok, stack) = evalScriptSigPushes(@[])
    check ok
    check stack.len == 0

  test "OP_0 → stack has empty byte vector":
    let (ok, stack) = evalScriptSigPushes(@[0x00'u8])
    check ok
    check stack.len == 1
    check stack[0].len == 0

  test "direct push of 3 bytes":
    let (ok, stack) = evalScriptSigPushes(@[0x03'u8, 0x01, 0x02, 0x03])
    check ok
    check stack.len == 1
    check stack[0] == @[0x01'u8, 0x02, 0x03]

  test "OP_PUSHDATA1":
    var script = @[0x4c'u8, 0x03'u8, 0xaa'u8, 0xbb, 0xcc]
    let (ok, stack) = evalScriptSigPushes(script)
    check ok
    check stack[0] == @[0xaa'u8, 0xbb, 0xcc]

  test "OP_1 pushes @[1]":
    let (ok, stack) = evalScriptSigPushes(@[0x51'u8])  # OP_1
    check ok
    check stack.len == 1
    check stack[0] == @[0x01'u8]

  test "OP_16 pushes @[16]":
    let (ok, stack) = evalScriptSigPushes(@[0x60'u8])  # OP_16
    check ok
    check stack.len == 1
    check stack[0] == @[0x10'u8]

  test "non-push opcode → fail":
    let (ok, _) = evalScriptSigPushes(@[byte(OP_DUP)])
    check not ok

  test "truncated push → fail":
    # Claims to push 5 bytes but only 2 follow
    let (ok, _) = evalScriptSigPushes(@[0x05'u8, 0x01'u8, 0x02'u8])
    check not ok

  test "multiple pushes build correct stack":
    # Push 2 bytes, then push 1 byte
    let script = @[0x02'u8, 0xaa'u8, 0xbb'u8, 0x01'u8, 0xcc'u8]
    let (ok, stack) = evalScriptSigPushes(script)
    check ok
    check stack.len == 2
    check stack[0] == @[0xaa'u8, 0xbb'u8]
    check stack[1] == @[0xcc'u8]
