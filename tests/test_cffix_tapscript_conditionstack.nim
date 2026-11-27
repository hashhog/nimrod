## cffix-nimrod-tapscript-conditionstack
##
## Finding (fingerprint nimrod/script/tapscript-condition-stack-linear-scan):
##   The interpreter kept IF/NOTIF/ELSE/ENDIF state in a seq[bool] and,
##   before every opcode, walked the whole seq to decide whether the current
##   branch executes. Tapscript lifts the 10,000-byte script limit and the
##   201-op limit, so the leaf
##       OP_1 OP_IF  (x N)   OP_ENDIF (x N)   OP_1
##   costs about 1.5 * N^2 element visits. A standard 400 kWU transaction
##   fits N ~ 133k. It is reached from block verification and from mempool
##   accept.
##
## Core: ConditionStack (bitcoin-core/src/script/interpreter.cpp:273-320)
##   stores only the size and the position of the first false entry, so each
##   opcode costs O(1).
##
## The fix replaces the seq[bool] with a ConditionStack of that shape. It must
## not change any verdict, so besides the cost tests this file pins the
## verdicts: hand cases under base and tapscript sigversions, deep false
## regions, a P2TR script-path spend of the nested leaf, a seeded random
## differential against a reference model that keeps an explicit seq[bool]
## (the pre-fix semantics), and a direct check of the ConditionStack against
## a seq[bool] under random push/pop/toggle sequences.
##
## Procs the fix adds are only touched under `when declared(ConditionStack)`,
## so this file compiles on master and fails there by name.

import unittest2
import std/[monotimes, times, random, sequtils]
import ../src/script/interpreter
import ../src/primitives/[types, serialize]
import ../src/crypto/secp256k1

# --- fixtures -----------------------------------------------------------------

proc nestedIfLeaf(n: int): seq[byte] =
  ## OP_1 OP_IF (x n), OP_ENDIF (x n), OP_1
  result = newSeqOfCap[byte](3 * n + 1)
  for i in 0 ..< n:
    result.add OP_1
    result.add OP_IF
  for i in 0 ..< n:
    result.add OP_ENDIF
  result.add OP_1

proc tapCtx(): SigCheckContext =
  SigCheckContext(tx: Transaction(), inputIndex: 0, amount: Satoshi(0),
                  sigVersion: sigTapscript, codesepPos: 0xFFFFFFFF'u32)

proc ctxFor(sv: SigVersion): SigCheckContext =
  SigCheckContext(tx: Transaction(), inputIndex: 0, amount: Satoshi(0),
                  sigVersion: sv, codesepPos: 0xFFFFFFFF'u32)

type EvalOut = object
  err: ScriptError
  stack: seq[seq[byte]]

proc run(script: seq[byte], sv: SigVersion): EvalOut =
  var interp = newInterpreter()
  let ctx = ctxFor(sv)
  result.err = interp.eval(script, ctx)
  result.stack = interp.stack

proc timeEval(script: seq[byte], reps: int): float =
  ## Fastest of `reps` evaluations, in seconds.
  result = Inf
  let ctx = tapCtx()
  for r in 0 ..< reps:
    var interp = newInterpreter()
    let t0 = getMonoTime()
    let err = interp.eval(script, ctx)
    let dt = (getMonoTime() - t0).inNanoseconds.float / 1e9
    doAssert err == seOk
    if dt < result: result = dt

# P2TR script-path fixture (same construction as test_taproot_commitment.nim).
proc trivialTx(): Transaction =
  result = Transaction()
  result.version = 2
  result.inputs = @[TxIn(prevOut: OutPoint(txid: default(TxId), vout: 0),
                         scriptSig: @[], sequence: 0xffffffff'u32)]
  result.outputs = @[TxOut(value: Satoshi(0), scriptPubKey: @[])]
  result.lockTime = 0

proc tapleafHashOf(tapscript: seq[byte]): array[32, byte] =
  var leafData: seq[byte]
  leafData.add(0xC0'u8)
  var w = BinaryWriter()
  w.writeVarBytes(tapscript)
  leafData.add(w.data)
  taggedHash("TapLeaf", leafData)

proc scriptPathSpend(leaf: seq[byte]): ScriptError =
  ## Spend a P2TR output whose only leaf is `leaf`, through the script path.
  var priv: PrivateKey
  priv[31] = 0x01'u8
  let compressed = derivePublicKey(priv)
  var ipk: array[32, byte]
  for i in 0 ..< 32: ipk[i] = compressed[1 + i]
  let root = tapleafHashOf(leaf)
  var tweakData: seq[byte]
  for b in ipk: tweakData.add b
  for b in root: tweakData.add b
  let (q, parity) = tweakXonlyPubkey(ipk, taggedHash("TapTweak", tweakData))
  var cb = @[byte(0xC0'u8 or uint8(parity and 0x01))]
  for b in ipk: cb.add b
  verifyWitnessProgramWithError(@[leaf, cb], 1, @q, trivialTx(), 0,
                                Satoshi(0), {sfWitness, sfTaproot})

# Reference model: the pre-fix semantics, with an explicit seq[bool] and the
# "execute only when no entry is false" rule. Covers the opcodes the random
# scripts use. Values on the stack are only @[] and @[1], so they are always
# minimal and toBool(v) == (v.len > 0).
proc model(script: seq[byte]): EvalOut =
  var st: seq[seq[byte]]
  var ex: seq[bool]
  template fail(e: ScriptError) =
    result.err = e
    return
  for op in script:
    if not ex.allIt(it):
      case op
      of OP_IF, OP_NOTIF: ex.add false
      of OP_ELSE:
        if ex.len == 0: fail seUnbalancedConditional
        ex[^1] = not ex[^1]
      of OP_ENDIF:
        if ex.len == 0: fail seUnbalancedConditional
        discard ex.pop()
      else: discard
      continue
    case op
    of OP_0: st.add newSeq[byte]()
    of OP_1: st.add @[1'u8]
    of OP_IF, OP_NOTIF:
      if st.len < 1: fail seInvalidStack
      var c = st.pop().len > 0
      if op == OP_NOTIF: c = not c
      ex.add c
    of OP_ELSE:
      if ex.len == 0: fail seUnbalancedConditional
      ex[^1] = not ex[^1]
    of OP_ENDIF:
      if ex.len == 0: fail seUnbalancedConditional
      discard ex.pop()
    of OP_DUP:
      if st.len < 1: fail seInvalidStack
      st.add st[^1]
    of OP_DROP:
      if st.len < 1: fail seInvalidStack
      discard st.pop()
    of OP_VERIFY:
      if st.len < 1: fail seInvalidStack
      if st.pop().len == 0: fail seVerify
    of OP_RETURN: fail seOpReturn
    else: doAssert false, "model: opcode not covered"
  if ex.len > 0: fail seUnbalancedConditional
  result.err = seOk
  result.stack = st

const
  T = @[OP_1]
  F = @[OP_0]

suite "cffix tapscript condition stack: nested OP_IF cost is linear (Core ConditionStack)":

  test "IF-state checks per opcode do not grow with nesting depth (deterministic, N=2k vs 4k)":
    when declared(ConditionStack):
      var checks: array[2, int]
      for i, n in [2000, 4000]:
        var interp = newInterpreter()
        let err = interp.eval(nestedIfLeaf(n), tapCtx())
        check err == seOk
        check interp.stack == @[@[1'u8]]
        checks[i] = interp.condStack.checks
      let ratio = checks[1].float / checks[0].float
      let msg = "condStack checks: N=2000 " & $checks[0] & ", N=4000 " &
        $checks[1] & ", ratio " & $ratio
      echo "  [cffix] ", msg
      checkpoint msg
      # O(1) per opcode: one check for each of the 3N+1 opcodes, ratio ~2.
      # A scan of the whole stack per opcode is ~1.5 N^2 visits, ratio ~4.
      check checks[0] <= 3 * 2000 + 1
      check ratio < 3.0
    else:
      checkpoint "no ConditionStack in the interpreter: IF state is a " &
        "seq[bool] scanned in full before every opcode (O(depth) per opcode)"
      check false

  test "nested OP_IF leaf time grows linearly, not quadratically (N=4k vs 16k)":
    let tSmall = timeEval(nestedIfLeaf(4000), 7)
    let tBig = timeEval(nestedIfLeaf(16000), 3)
    let ratio = tBig / tSmall
    let msg = "fastest eval: N=4000 " & $(tSmall * 1e3) & " ms, N=16000 " &
      $(tBig * 1e3) & " ms, ratio " & $ratio
    echo "  [cffix] ", msg
    checkpoint msg
    # Linear ~4, quadratic ~16.
    check ratio <= 8.0

  test "P2TR script-path spend of the nested leaf verifies (N=4000) and an unbalanced one fails":
    check scriptPathSpend(nestedIfLeaf(4000)) == seOk
    var unbalanced = nestedIfLeaf(4000)
    unbalanced.delete(unbalanced.len - 2)   # drop one OP_ENDIF
    check scriptPathSpend(unbalanced) == seUnbalancedConditional

suite "cffix tapscript condition stack: verdicts unchanged":

  test "hand cases under base and tapscript sigversions":
    type Case = tuple[name: string, script: seq[byte], err: ScriptError,
                      stack: seq[seq[byte]]]
    let one = @[1'u8]
    let none = newSeq[byte]()
    let cases: seq[Case] = @[
      ("if true", T & @[OP_IF, OP_1, OP_ENDIF], seOk, @[one]),
      ("if false", F & @[OP_IF, OP_1, OP_ENDIF], seOk, @[]),
      ("notif false", F & @[OP_NOTIF, OP_1, OP_ENDIF], seOk, @[one]),
      ("notif true", T & @[OP_NOTIF, OP_1, OP_ENDIF], seOk, @[]),
      ("if/else true", T & @[OP_IF, OP_1, OP_ELSE, OP_0, OP_ENDIF], seOk, @[one]),
      ("if/else false", F & @[OP_IF, OP_1, OP_ELSE, OP_0, OP_ENDIF], seOk, @[none]),
      ("double else", T & @[OP_IF, OP_1, OP_ELSE, OP_0, OP_ELSE, OP_1, OP_ENDIF],
        seOk, @[one, one]),
      ("triple else", F & @[OP_IF, OP_1, OP_ELSE, OP_0, OP_ELSE, OP_1, OP_ELSE,
        OP_0, OP_ENDIF], seOk, @[none, none]),
      ("else under false parent",
        F & @[OP_IF, OP_1, OP_IF, OP_1, OP_ELSE, OP_0, OP_ENDIF, OP_ENDIF], seOk, @[]),
      ("else under false grandparent",
        F & @[OP_IF, OP_1, OP_IF, OP_1, OP_IF, OP_1, OP_ELSE, OP_0, OP_ENDIF,
        OP_ENDIF, OP_ENDIF], seOk, @[]),
      ("else of false parent re-enables nested true",
        F & @[OP_IF, OP_RETURN, OP_ELSE, OP_1, OP_IF, OP_1, OP_ENDIF, OP_ENDIF],
        seOk, @[one]),
      ("resume after inner false endif",
        T & @[OP_IF, OP_0, OP_IF, OP_RETURN, OP_ENDIF, OP_1, OP_ENDIF], seOk, @[one]),
      ("resume after outer else",
        F & @[OP_IF, OP_1, OP_IF, OP_RETURN, OP_ENDIF, OP_ELSE, OP_1, OP_ENDIF],
        seOk, @[one]),
      ("false at bottom, true above, then else at bottom",
        F & @[OP_IF, OP_1, OP_IF, OP_1, OP_IF, OP_RETURN, OP_ENDIF, OP_ENDIF,
        OP_ELSE, OP_1, OP_ENDIF], seOk, @[one]),
      ("toggle non-first false is unobservable",
        F & @[OP_IF, OP_0, OP_IF, OP_ELSE, OP_RETURN, OP_ENDIF, OP_ENDIF, OP_1],
        seOk, @[one]),
      ("executed return", T & @[OP_IF, OP_RETURN, OP_ENDIF], seOpReturn, @[]),
      ("skipped return", F & @[OP_IF, OP_RETURN, OP_ENDIF, OP_1], seOk, @[one]),
      ("executed verify false", T & @[OP_IF, OP_0, OP_VERIFY, OP_ENDIF], seVerify, @[]),
      ("skipped verify false", F & @[OP_IF, OP_0, OP_VERIFY, OP_ENDIF], seOk, @[]),
      ("executed drop underflow", T & @[OP_IF, OP_DROP, OP_ENDIF], seInvalidStack, @[]),
      ("skipped drop underflow", F & @[OP_IF, OP_DROP, OP_ENDIF], seOk, @[]),
      ("if with empty stack", @[OP_IF, OP_ENDIF], seInvalidStack, @[]),
      ("lone else", @[OP_ELSE], seUnbalancedConditional, @[]),
      ("lone endif", @[OP_ENDIF], seUnbalancedConditional, @[]),
      ("missing endif", T & @[OP_IF], seUnbalancedConditional, @[]),
      ("missing endif in false branch", F & @[OP_IF], seUnbalancedConditional, @[]),
      ("extra endif", T & @[OP_IF, OP_ENDIF, OP_ENDIF], seUnbalancedConditional, @[]),
      ("else after close", T & @[OP_IF, OP_ENDIF, OP_ELSE], seUnbalancedConditional, @[]),
      ("extra endif inside false branch",
        F & @[OP_IF, OP_ENDIF, OP_ENDIF], seUnbalancedConditional, @[]),
    ]
    for sv in [sigBase, sigTapscript]:
      for c in cases:
        let r = run(c.script, sv)
        checkpoint $sv & " / " & c.name & ": err=" & $r.err
        check r.err == c.err
        if c.err == seOk:
          check r.stack == c.stack
        # The reference model agrees with every hand case.
        let m = model(c.script)
        check m.err == c.err

  test "deep regions (tapscript): false under 3000 trues, 3000 trues under a false, missing endif":
    # Base script has the 201-op / 10,000-byte limits, so these run only
    # under tapscript.
    # 3000 true IFs, then a false IF guarding RETURN, all closed, then OP_1.
    var a: seq[byte]
    for i in 0 ..< 3000: a.add @[OP_1, OP_IF]
    a.add @[OP_0, OP_IF, OP_RETURN, OP_ENDIF]
    for i in 0 ..< 3000: a.add OP_ENDIF
    a.add OP_1
    let ra = run(a, sigTapscript)
    check ra.err == seOk
    check ra.stack == @[@[1'u8]]
    # A false IF, then 3000 nested IF/RETURN that must all be skipped, then
    # the outer ELSE runs.
    var b = @[OP_0, OP_IF]
    for i in 0 ..< 3000: b.add @[OP_1, OP_IF, OP_RETURN]
    for i in 0 ..< 3000: b.add OP_ENDIF
    b.add @[OP_ELSE, OP_1, OP_ENDIF]
    let rb = run(b, sigTapscript)
    check rb.err == seOk
    check rb.stack == @[@[1'u8]]
    # The same with the outer OP_ENDIF missing.
    var c = b
    c.setLen(c.len - 1)
    check run(c, sigTapscript).err == seUnbalancedConditional

  test "seeded differential: 20,000 random scripts match the seq[bool] model":
    const ops = [OP_0, OP_1, OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF, OP_DUP,
                 OP_DROP, OP_VERIFY, OP_RETURN]
    # Weight control flow up so deep and unbalanced shapes are common.
    const weights = [3, 4, 4, 2, 3, 4, 1, 1, 1, 1]
    var pool: seq[byte]
    for i, op in ops:
      for k in 0 ..< weights[i]: pool.add op
    var rng = initRand(0x5c0de_c0d5)
    var seen: array[ScriptError, int]
    var mismatches = 0
    for iter in 0 ..< 20_000:
      let len = rng.rand(1 .. 40)
      var s = newSeq[byte](len)
      for j in 0 ..< len: s[j] = pool[rng.rand(pool.high)]
      let m = model(s)
      inc seen[m.err]
      for sv in [sigBase, sigTapscript]:
        let r = run(s, sv)
        if r.err != m.err or (m.err == seOk and r.stack != m.stack):
          inc mismatches
          if mismatches <= 5:
            checkpoint $sv & " mismatch on " & $s & ": node " & $r.err &
              " model " & $m.err
    check mismatches == 0
    let msg = "outcome classes: ok " & $seen[seOk] & ", unbalanced " &
      $seen[seUnbalancedConditional] & ", return " & $seen[seOpReturn] &
      ", verify " & $seen[seVerify] & ", underflow " & $seen[seInvalidStack]
    echo "  [cffix] ", msg
    checkpoint msg
    for e in [seOk, seUnbalancedConditional, seOpReturn, seVerify, seInvalidStack]:
      check seen[e] >= 100

  test "ConditionStack matches a seq[bool] under random push/pop/toggle":
    when declared(ConditionStack):
      var rng = initRand(0xc0_57ac)
      var bad = 0
      for iter in 0 ..< 2000:
        var cs = initConditionStack()
        var ref0: seq[bool]
        for step in 0 ..< 200:
          let k = rng.rand(0 .. 3)
          if k <= 1 or ref0.len == 0:
            let f = rng.rand(0 .. 2) != 0
            cs.pushBack(f); ref0.add f
          elif k == 2:
            cs.popBack(); discard ref0.pop()
          else:
            cs.toggleTop(); ref0[^1] = not ref0[^1]
          if cs.allTrue() != ref0.allIt(it) or cs.empty != (ref0.len == 0):
            inc bad
      check bad == 0
    else:
      skip()
