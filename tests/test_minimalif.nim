## Tests for SCRIPT_VERIFY_MINIMALIF (BIP/consensus)
##
## For OP_IF/OP_NOTIF in witness programs:
## - Tapscript (v1): MINIMALIF is unconditional consensus - argument must be
##   exactly empty (false) or exactly @[0x01] (true)
## - Witness v0: MINIMALIF is enforced when sfMinimalIf flag is set
##
## Any other value (e.g., @[0x02], @[0x00], @[0x01, 0x00]) must be rejected.

import unittest2
import ../src/script/interpreter
import ../src/primitives/types

suite "minimalif - witness v0 with sfMinimalIf flag":
  test "OP_IF with @[0x01] passes (true)":
    # @[0x01] is the only acceptable true value
    var interp = newInterpreter({sfMinimalIf})
    interp.push(@[0x01'u8])  # Minimal true

    let script = @[OP_IF, OP_1, OP_ELSE, OP_2, OP_ENDIF]

    var emptyTx = Transaction()
    var ctx = SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigWitnessV0,
      codesepPos: 0xFFFFFFFF'u32
    )

    let err = interp.eval(script, ctx)
    check err == seOk
    # Should take true branch, result = 1
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 1

  test "OP_IF with empty passes (false)":
    # Empty is the only acceptable false value
    var interp = newInterpreter({sfMinimalIf})
    interp.push(@[])  # Minimal false (empty)

    let script = @[OP_IF, OP_1, OP_ELSE, OP_2, OP_ENDIF]

    var emptyTx = Transaction()
    var ctx = SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigWitnessV0,
      codesepPos: 0xFFFFFFFF'u32
    )

    let err = interp.eval(script, ctx)
    check err == seOk
    # Should take else branch, result = 2
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 2

  test "OP_IF with @[0x02] fails - not minimal true":
    # @[0x02] is truthy but not minimal (only @[0x01] is acceptable)
    var interp = newInterpreter({sfMinimalIf})
    interp.push(@[0x02'u8])

    let script = @[OP_IF, OP_1, OP_ELSE, OP_2, OP_ENDIF]

    var emptyTx = Transaction()
    var ctx = SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigWitnessV0,
      codesepPos: 0xFFFFFFFF'u32
    )

    let err = interp.eval(script, ctx)
    check err == seMinimalIf

  test "OP_IF with @[0x00] fails - not minimal false":
    # @[0x00] is falsy but not minimal (only empty is acceptable)
    var interp = newInterpreter({sfMinimalIf})
    interp.push(@[0x00'u8])

    let script = @[OP_IF, OP_1, OP_ELSE, OP_2, OP_ENDIF]

    var emptyTx = Transaction()
    var ctx = SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigWitnessV0,
      codesepPos: 0xFFFFFFFF'u32
    )

    let err = interp.eval(script, ctx)
    check err == seMinimalIf

  test "OP_IF with @[0x01, 0x00] fails - multi-byte not allowed":
    # Multi-byte values are never allowed
    var interp = newInterpreter({sfMinimalIf})
    interp.push(@[0x01'u8, 0x00])

    let script = @[OP_IF, OP_1, OP_ELSE, OP_2, OP_ENDIF]

    var emptyTx = Transaction()
    var ctx = SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigWitnessV0,
      codesepPos: 0xFFFFFFFF'u32
    )

    let err = interp.eval(script, ctx)
    check err == seMinimalIf

  test "OP_IF with @[0x80] fails - negative zero not minimal":
    # @[0x80] is negative zero, falsy but not minimal
    var interp = newInterpreter({sfMinimalIf})
    interp.push(@[0x80'u8])

    let script = @[OP_IF, OP_1, OP_ELSE, OP_2, OP_ENDIF]

    var emptyTx = Transaction()
    var ctx = SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigWitnessV0,
      codesepPos: 0xFFFFFFFF'u32
    )

    let err = interp.eval(script, ctx)
    check err == seMinimalIf

  test "OP_NOTIF with @[0x01] passes (evaluates false branch)":
    var interp = newInterpreter({sfMinimalIf})
    interp.push(@[0x01'u8])  # Minimal true

    let script = @[OP_NOTIF, OP_1, OP_ELSE, OP_2, OP_ENDIF]

    var emptyTx = Transaction()
    var ctx = SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigWitnessV0,
      codesepPos: 0xFFFFFFFF'u32
    )

    let err = interp.eval(script, ctx)
    check err == seOk
    # NOTIF with true -> takes else branch, result = 2
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 2

  test "OP_NOTIF with @[0x02] fails - not minimal":
    var interp = newInterpreter({sfMinimalIf})
    interp.push(@[0x02'u8])

    let script = @[OP_NOTIF, OP_1, OP_ELSE, OP_2, OP_ENDIF]

    var emptyTx = Transaction()
    var ctx = SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigWitnessV0,
      codesepPos: 0xFFFFFFFF'u32
    )

    let err = interp.eval(script, ctx)
    check err == seMinimalIf

suite "minimalif - witness v0 without sfMinimalIf flag":
  test "OP_IF with @[0x02] passes without sfMinimalIf":
    # Without the flag, non-minimal values should be allowed
    var interp = newInterpreter()  # No sfMinimalIf
    interp.push(@[0x02'u8])

    let script = @[OP_IF, OP_1, OP_ELSE, OP_2, OP_ENDIF]

    var emptyTx = Transaction()
    var ctx = SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigWitnessV0,
      codesepPos: 0xFFFFFFFF'u32
    )

    let err = interp.eval(script, ctx)
    check err == seOk
    # Should take true branch since 0x02 is truthy
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 1

  test "OP_IF with @[0x00] passes without sfMinimalIf":
    var interp = newInterpreter()  # No sfMinimalIf
    interp.push(@[0x00'u8])

    let script = @[OP_IF, OP_1, OP_ELSE, OP_2, OP_ENDIF]

    var emptyTx = Transaction()
    var ctx = SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigWitnessV0,
      codesepPos: 0xFFFFFFFF'u32
    )

    let err = interp.eval(script, ctx)
    check err == seOk
    # Should take else branch since 0x00 is falsy
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 2

suite "minimalif - tapscript (unconditional consensus)":
  test "OP_IF with @[0x01] passes in tapscript":
    var interp = newInterpreter({sfTaproot})
    interp.push(@[0x01'u8])

    let script = @[OP_IF, OP_1, OP_ELSE, OP_2, OP_ENDIF]

    var emptyTx = Transaction()
    var ctx = SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigTapscript,  # Tapscript context
      codesepPos: 0xFFFFFFFF'u32
    )

    let err = interp.eval(script, ctx)
    check err == seOk
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 1

  test "OP_IF with empty passes in tapscript":
    var interp = newInterpreter({sfTaproot})
    interp.push(@[])

    let script = @[OP_IF, OP_1, OP_ELSE, OP_2, OP_ENDIF]

    var emptyTx = Transaction()
    var ctx = SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigTapscript,
      codesepPos: 0xFFFFFFFF'u32
    )

    let err = interp.eval(script, ctx)
    check err == seOk
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 2

  test "OP_IF with @[0x02] fails in tapscript (consensus)":
    # In tapscript, MINIMALIF is consensus - no flag needed
    var interp = newInterpreter({sfTaproot})
    interp.push(@[0x02'u8])

    let script = @[OP_IF, OP_1, OP_ELSE, OP_2, OP_ENDIF]

    var emptyTx = Transaction()
    var ctx = SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigTapscript,
      codesepPos: 0xFFFFFFFF'u32
    )

    let err = interp.eval(script, ctx)
    check err == seTapscriptMinimalIf

  test "OP_IF with @[0x00] fails in tapscript (consensus)":
    var interp = newInterpreter({sfTaproot})
    interp.push(@[0x00'u8])

    let script = @[OP_IF, OP_1, OP_ELSE, OP_2, OP_ENDIF]

    var emptyTx = Transaction()
    var ctx = SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigTapscript,
      codesepPos: 0xFFFFFFFF'u32
    )

    let err = interp.eval(script, ctx)
    check err == seTapscriptMinimalIf

  test "OP_IF with @[0x01, 0x00] fails in tapscript (consensus)":
    var interp = newInterpreter({sfTaproot})
    interp.push(@[0x01'u8, 0x00])

    let script = @[OP_IF, OP_1, OP_ELSE, OP_2, OP_ENDIF]

    var emptyTx = Transaction()
    var ctx = SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigTapscript,
      codesepPos: 0xFFFFFFFF'u32
    )

    let err = interp.eval(script, ctx)
    check err == seTapscriptMinimalIf

  test "OP_NOTIF with @[0x02] fails in tapscript":
    var interp = newInterpreter({sfTaproot})
    interp.push(@[0x02'u8])

    let script = @[OP_NOTIF, OP_1, OP_ELSE, OP_2, OP_ENDIF]

    var emptyTx = Transaction()
    var ctx = SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigTapscript,
      codesepPos: 0xFFFFFFFF'u32
    )

    let err = interp.eval(script, ctx)
    check err == seTapscriptMinimalIf

suite "minimalif - legacy scripts":
  test "OP_IF with @[0x02] passes in legacy script":
    # Legacy scripts do not enforce MINIMALIF
    var interp = newInterpreter()
    interp.push(@[0x02'u8])

    let script = @[OP_IF, OP_1, OP_ELSE, OP_2, OP_ENDIF]

    var emptyTx = Transaction()
    var ctx = SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigBase,  # Legacy context
      codesepPos: 0xFFFFFFFF'u32
    )

    let err = interp.eval(script, ctx)
    check err == seOk
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 1

  test "OP_IF with @[0x00] passes in legacy script":
    var interp = newInterpreter()
    interp.push(@[0x00'u8])

    let script = @[OP_IF, OP_1, OP_ELSE, OP_2, OP_ENDIF]

    var emptyTx = Transaction()
    var ctx = SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigBase,
      codesepPos: 0xFFFFFFFF'u32
    )

    let err = interp.eval(script, ctx)
    check err == seOk
    # @[0x00] is falsy
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 2

  test "OP_IF with multi-byte passes in legacy script":
    var interp = newInterpreter()
    interp.push(@[0x01'u8, 0x00, 0x00])

    let script = @[OP_IF, OP_1, OP_ELSE, OP_2, OP_ENDIF]

    var emptyTx = Transaction()
    var ctx = SigCheckContext(
      tx: emptyTx,
      inputIndex: 0,
      amount: Satoshi(0),
      sigVersion: sigBase,
      codesepPos: 0xFFFFFFFF'u32
    )

    let err = interp.eval(script, ctx)
    check err == seOk
    # Multi-byte with non-zero is truthy
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 1

suite "op_if - basic functionality":
  test "OP_IF true branch":
    var interp = newInterpreter()
    let script = @[OP_1, OP_IF, OP_2, OP_ELSE, OP_3, OP_ENDIF]
    let res = interp.execute(script)
    check res == true
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 2

  test "OP_IF false branch":
    var interp = newInterpreter()
    let script = @[OP_0, OP_IF, OP_2, OP_ELSE, OP_3, OP_ENDIF]
    let res = interp.execute(script)
    check res == true
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 3

  test "OP_NOTIF true becomes false branch":
    var interp = newInterpreter()
    let script = @[OP_1, OP_NOTIF, OP_2, OP_ELSE, OP_3, OP_ENDIF]
    let res = interp.execute(script)
    check res == true
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 3

  test "OP_NOTIF false becomes true branch":
    var interp = newInterpreter()
    let script = @[OP_0, OP_NOTIF, OP_2, OP_ELSE, OP_3, OP_ENDIF]
    let res = interp.execute(script)
    check res == true
    let (val, ok) = toScriptNum(interp.peek())
    check ok == true
    check val == 2
