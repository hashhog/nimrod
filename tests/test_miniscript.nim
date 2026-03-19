## Tests for Miniscript parsing, type checking, compilation, and satisfaction

import std/[unittest, tables, options, sequtils, strutils]
import ../src/wallet/miniscript
import ../src/crypto/hashing
import ../src/script/interpreter

# Test key for examples
const
  TestKey1Hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
  TestKey2Hex = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
  TestKey3Hex = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"

proc parseHexBytes(s: string): seq[byte] =
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[i*2 ..< i*2+2]))

proc toPublicKey(s: string): PublicKey =
  let bytes = parseHexBytes(s)
  copyMem(addr result[0], addr bytes[0], 33)

let
  key1 = toPublicKey(TestKey1Hex)
  key2 = toPublicKey(TestKey2Hex)
  key3 = toPublicKey(TestKey3Hex)

# =============================================================================
# Parsing Tests
# =============================================================================

suite "miniscript parsing":
  test "parse pk_k":
    let node = parseMiniscript("pk_k(" & TestKey1Hex & ")")
    check node.kind == MsPkK
    check node.key == key1

  test "parse pk (alias for pk_k)":
    let node = parseMiniscript("pk(" & TestKey1Hex & ")")
    check node.kind == MsPkK

  test "parse pkh":
    let node = parseMiniscript("pkh(" & TestKey1Hex & ")")
    check node.kind == MsPkH
    check node.key == key1

  test "parse older":
    let node = parseMiniscript("older(144)")
    check node.kind == MsOlder
    check node.lockValue == 144

  test "parse after":
    let node = parseMiniscript("after(500000000)")
    check node.kind == MsAfter
    check node.lockValue == 500000000

  test "parse sha256":
    let hashHex = "6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333"
    let node = parseMiniscript("sha256(" & hashHex & ")")
    check node.kind == MsSha256

  test "parse hash160":
    let hashHex = "e9c3dd0c07aac76179ebc76a6c78d4d67c6c160a"
    let node = parseMiniscript("hash160(" & hashHex & ")")
    check node.kind == MsHash160

  test "parse wrappers":
    # a: requires B type, c:pk_k converts K to B
    let nodeA = parseMiniscript("a:c:pk_k(" & TestKey1Hex & ")")
    check nodeA.kind == MsWrapA
    check nodeA.sub.kind == MsWrapC

    # s: requires Bo type, c:pk_k is B but needs o flag
    # Use older which has z (and thus o-compatible)
    let nodeS = parseMiniscript("s:c:pk_k(" & TestKey1Hex & ")")
    check nodeS.kind == MsWrapS

    let nodeC = parseMiniscript("c:pk_k(" & TestKey1Hex & ")")
    check nodeC.kind == MsWrapC

    # v: requires B type
    let nodeV = parseMiniscript("v:c:pk_k(" & TestKey1Hex & ")")
    check nodeV.kind == MsWrapV

  test "parse and_v":
    # and_v requires X:V and any Y that produces B/V/K
    let node = parseMiniscript("and_v(v:c:pk_k(" & TestKey1Hex & "),pk_k(" & TestKey2Hex & "))")
    check node.kind == MsAndV
    check node.left.kind == MsWrapV
    check node.right.kind == MsPkK

  test "parse and_b":
    let node = parseMiniscript("and_b(pk_k(" & TestKey1Hex & "),s:pk_k(" & TestKey2Hex & "))")
    check node.kind == MsAndB

  test "parse or_b":
    let node = parseMiniscript("or_b(pk_k(" & TestKey1Hex & "),s:pk_k(" & TestKey2Hex & "))")
    check node.kind == MsOrB

  test "parse or_c":
    let node = parseMiniscript("or_c(pk_k(" & TestKey1Hex & "),v:pk_k(" & TestKey2Hex & "))")
    check node.kind == MsOrC

  test "parse or_d":
    let node = parseMiniscript("or_d(pk_k(" & TestKey1Hex & "),pk_k(" & TestKey2Hex & "))")
    check node.kind == MsOrD

  test "parse or_i":
    let node = parseMiniscript("or_i(pk_k(" & TestKey1Hex & "),pk_k(" & TestKey2Hex & "))")
    check node.kind == MsOrI

  test "parse andor":
    let node = parseMiniscript("andor(pk_k(" & TestKey1Hex & "),pk_k(" & TestKey2Hex & "),pk_k(" & TestKey3Hex & "))")
    check node.kind == MsAndOr

  test "parse thresh":
    let node = parseMiniscript("thresh(2,pk_k(" & TestKey1Hex & "),s:pk_k(" & TestKey2Hex & "),s:pk_k(" & TestKey3Hex & "))")
    check node.kind == MsThresh
    check node.threshold == 2
    check node.subs.len == 3

  test "parse multi":
    let node = parseMiniscript("multi(2," & TestKey1Hex & "," & TestKey2Hex & "," & TestKey3Hex & ")")
    check node.kind == MsMulti
    check node.k == 2
    check node.keys.len == 3

  test "parse syntactic sugar l: and u:":
    let nodeL = parseMiniscript("l:pk_k(" & TestKey1Hex & ")")
    check nodeL.kind == MsOrI
    check nodeL.left.kind == MsJust0
    check nodeL.right.kind == MsPkK

    let nodeU = parseMiniscript("u:pk_k(" & TestKey1Hex & ")")
    check nodeU.kind == MsOrI
    check nodeU.left.kind == MsPkK
    check nodeU.right.kind == MsJust0

  test "parse syntactic sugar t:":
    let nodeT = parseMiniscript("t:pk_k(" & TestKey1Hex & ")")
    check nodeT.kind == MsAndV
    check nodeT.left.kind == MsPkK
    check nodeT.right.kind == MsJust1

  test "parse complex nested expression":
    let ms = "andor(pk_k(" & TestKey1Hex & "),or_i(pk_k(" & TestKey2Hex & "),older(1000)),pk_k(" & TestKey3Hex & "))"
    let node = parseMiniscript(ms)
    check node.kind == MsAndOr
    check node.x.kind == MsPkK
    check node.y.kind == MsOrI
    check node.z.kind == MsPkK

  test "invalid miniscript raises error":
    expect(MiniscriptError):
      discard parseMiniscript("invalid()")

    expect(MiniscriptError):
      discard parseMiniscript("pk_k()")  # No key

    expect(MiniscriptError):
      discard parseMiniscript("multi(0," & TestKey1Hex & ")")  # Invalid k

# =============================================================================
# Type System Tests
# =============================================================================

suite "miniscript type system":
  test "pk_k has type K":
    let node = parseMiniscript("pk_k(" & TestKey1Hex & ")")
    check node.msType.base == MsTypeK
    check node.msType.hasO
    check node.msType.hasN
    check node.msType.hasU
    check node.msType.hasD
    check node.msType.hasE
    check node.msType.hasM
    check node.msType.hasS

  test "c:pk_k has type B":
    let node = parseMiniscript("c:pk_k(" & TestKey1Hex & ")")
    check node.msType.base == MsTypeB
    check node.msType.hasU
    check node.msType.hasS

  test "v:pk_k has type V":
    let node = parseMiniscript("v:pk_k(" & TestKey1Hex & ")")
    check node.msType.base == MsTypeV
    check node.msType.hasF

  test "a:pk_k has type W":
    let node = parseMiniscript("a:pk_k(" & TestKey1Hex & ")")
    check node.msType.base == MsTypeW

  test "older has type B":
    let node = parseMiniscript("older(100)")
    check node.msType.base == MsTypeB
    check node.msType.hasZ
    check node.msType.hasF
    check node.msType.hasM

  test "and_v type propagation":
    let node = parseMiniscript("and_v(v:pk_k(" & TestKey1Hex & "),pk_k(" & TestKey2Hex & "))")
    check node.msType.base == MsTypeK

  test "and_b requires B and W":
    let node = parseMiniscript("and_b(pk_k(" & TestKey1Hex & "),s:pk_k(" & TestKey2Hex & "))")
    check node.msType.base == MsTypeB
    check node.msType.hasU

  test "multi has type B":
    let node = parseMiniscript("multi(2," & TestKey1Hex & "," & TestKey2Hex & ")")
    check node.msType.base == MsTypeB
    check node.msType.hasN
    check node.msType.hasU
    check node.msType.hasD
    check node.msType.hasE
    check node.msType.hasM
    check node.msType.hasS

  test "validateType returns true for valid miniscript":
    let node = parseMiniscript("c:pk_k(" & TestKey1Hex & ")")
    check validateType(node, MsP2WSH)

# =============================================================================
# Compilation Tests
# =============================================================================

suite "miniscript compilation":
  test "compile pk_k":
    let node = parseMiniscript("pk_k(" & TestKey1Hex & ")")
    let script = compile(node)
    # Should be: <33 bytes> <pubkey>
    check script.len == 34
    check script[0] == 33  # Push 33 bytes

  test "compile c:pk_k":
    let node = parseMiniscript("c:pk_k(" & TestKey1Hex & ")")
    let script = compile(node)
    # Should be: <pubkey> OP_CHECKSIG
    check script[^1] == OP_CHECKSIG

  test "compile older":
    let node = parseMiniscript("older(144)")
    let script = compile(node)
    # Should include OP_CHECKSEQUENCEVERIFY
    check OP_CHECKSEQUENCEVERIFY in script

  test "compile after":
    let node = parseMiniscript("after(500000)")
    let script = compile(node)
    check OP_CHECKLOCKTIMEVERIFY in script

  test "compile sha256":
    let hashHex = "6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333"
    let node = parseMiniscript("sha256(" & hashHex & ")")
    let script = compile(node)
    check OP_SHA256 in script
    check OP_EQUAL in script
    check OP_SIZE in script

  test "compile and_v":
    let node = parseMiniscript("and_v(v:pk_k(" & TestKey1Hex & "),pk_k(" & TestKey2Hex & "))")
    let script = compile(node)
    # Should have two pubkeys
    check script.len > 68  # Two 34-byte key pushes plus opcodes

  test "compile or_i":
    let node = parseMiniscript("or_i(pk_k(" & TestKey1Hex & "),pk_k(" & TestKey2Hex & "))")
    let script = compile(node)
    check OP_IF in script
    check OP_ELSE in script
    check OP_ENDIF in script

  test "compile multi":
    let node = parseMiniscript("multi(2," & TestKey1Hex & "," & TestKey2Hex & ")")
    let script = compile(node)
    check OP_CHECKMULTISIG in script
    check script[0] == 0x52  # OP_2

  test "compile thresh":
    let node = parseMiniscript("thresh(2,pk_k(" & TestKey1Hex & "),s:pk_k(" & TestKey2Hex & "),s:pk_k(" & TestKey3Hex & "))")
    let script = compile(node)
    check OP_ADD in script
    check OP_EQUAL in script

  test "compile v:X merges with CHECKSIG":
    let node = parseMiniscript("v:c:pk_k(" & TestKey1Hex & ")")
    let script = compile(node)
    # Should use OP_CHECKSIGVERIFY instead of OP_CHECKSIG OP_VERIFY
    check OP_CHECKSIGVERIFY in script
    check OP_CHECKSIG notin script

# =============================================================================
# Satisfaction Tests
# =============================================================================

suite "miniscript satisfaction":
  test "satisfy pk_k with available signature":
    let node = parseMiniscript("pk_k(" & TestKey1Hex & ")")

    var sigCtx = SigningContext.new()
    sigCtx.availableKeys = initTable[PublicKey, seq[byte]]()
    sigCtx.availableKeys[key1] = @[1'u8, 2, 3, 4]  # Dummy signature

    let res = satisfy(node, sigCtx)
    check res.sat.available == AvailYes
    check res.sat.stack.len == 1

  test "satisfy pk_k without signature":
    let node = parseMiniscript("pk_k(" & TestKey1Hex & ")")

    var sigCtx = SigningContext.new()
    sigCtx.availableKeys = initTable[PublicKey, seq[byte]]()

    let res = satisfy(node, sigCtx)
    check res.sat.available == AvailNo
    check res.dissat.available == AvailYes

  test "satisfy or_i chooses available branch":
    let node = parseMiniscript("or_i(pk_k(" & TestKey1Hex & "),pk_k(" & TestKey2Hex & "))")

    var sigCtx = SigningContext.new()
    sigCtx.availableKeys = initTable[PublicKey, seq[byte]]()
    sigCtx.availableKeys[key2] = @[5'u8, 6, 7, 8]

    let res = satisfy(node, sigCtx)
    check res.sat.available == AvailYes

  test "satisfy older with timelock check":
    let node = parseMiniscript("older(100)")

    var sigCtx = SigningContext.new()
    sigCtx.availableKeys = initTable[PublicKey, seq[byte]]()
    sigCtx.checkOlder = proc(n: uint32): bool = n <= 200

    let res = satisfy(node, sigCtx)
    check res.sat.available == AvailYes

  test "satisfy older with failed timelock":
    let node = parseMiniscript("older(100)")

    var sigCtx = SigningContext.new()
    sigCtx.availableKeys = initTable[PublicKey, seq[byte]]()
    sigCtx.checkOlder = proc(n: uint32): bool = false

    let res = satisfy(node, sigCtx)
    check res.sat.available == AvailNo

  test "satisfy sha256 with preimage":
    let preimage = @[0x01'u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                     0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                     0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                     0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20]
    let hash = sha256Single(preimage)
    var hashHex = ""
    for b in hash:
      hashHex.add(toHex(int(b), 2).toLowerAscii())

    let node = parseMiniscript("sha256(" & hashHex & ")")

    var sigCtx = SigningContext.new()
    sigCtx.availableKeys = initTable[PublicKey, seq[byte]]()
    sigCtx.availablePreimages32 = initTable[array[32, byte], seq[byte]]()
    sigCtx.availablePreimages32[hash] = preimage

    let res = satisfy(node, sigCtx)
    check res.sat.available == AvailYes
    check res.sat.stack.len == 1
    check res.sat.stack[0] == preimage

  test "satisfy multi with k signatures":
    let node = parseMiniscript("multi(2," & TestKey1Hex & "," & TestKey2Hex & "," & TestKey3Hex & ")")

    var sigCtx = SigningContext.new()
    sigCtx.availableKeys = initTable[PublicKey, seq[byte]]()
    sigCtx.availableKeys[key1] = @[0xAA'u8, 0xBB]
    sigCtx.availableKeys[key2] = @[0xCC'u8, 0xDD]

    let res = satisfy(node, sigCtx)
    check res.sat.available == AvailYes
    # Witness: dummy + 2 sigs = 3 elements
    check res.sat.stack.len == 3

  test "satisfy multi with insufficient signatures":
    let node = parseMiniscript("multi(2," & TestKey1Hex & "," & TestKey2Hex & "," & TestKey3Hex & ")")

    var sigCtx = SigningContext.new()
    sigCtx.availableKeys = initTable[PublicKey, seq[byte]]()
    sigCtx.availableKeys[key1] = @[0xAA'u8, 0xBB]
    # Only one signature, need 2

    let res = satisfy(node, sigCtx)
    check res.sat.available == AvailNo

  test "getWitness returns witness stack":
    let node = parseMiniscript("pk_k(" & TestKey1Hex & ")")

    var sigCtx = SigningContext.new()
    sigCtx.availableKeys = initTable[PublicKey, seq[byte]]()
    sigCtx.availableKeys[key1] = @[0x30'u8, 0x45]  # Dummy DER

    let witness = getWitness(node, sigCtx)
    check witness.isSome
    check witness.get.len == 1

# =============================================================================
# Analysis Tests
# =============================================================================

suite "miniscript analysis":
  test "maxWitnessSize for pk_k":
    let node = parseMiniscript("pk_k(" & TestKey1Hex & ")")
    let size = maxWitnessSize(node, MsP2WSH)
    check size == 73  # DER sig max

  test "maxWitnessSize for pk_k in tapscript":
    let node = parseMiniscript("pk_k(" & TestKey1Hex & ")", MsTapscript)
    let size = maxWitnessSize(node, MsTapscript)
    check size == 65  # Schnorr sig

  test "maxWitnessSize for multi":
    let node = parseMiniscript("multi(2," & TestKey1Hex & "," & TestKey2Hex & ")")
    let size = maxWitnessSize(node, MsP2WSH)
    # 2 sigs + dummy = 2*74 + 1 = 149
    check size > 140

  test "requiredKeys for pk_k":
    let node = parseMiniscript("pk_k(" & TestKey1Hex & ")")
    let keys = requiredKeys(node)
    check keys.len == 1
    check keys[0] == key1

  test "requiredKeys for multi":
    let node = parseMiniscript("multi(2," & TestKey1Hex & "," & TestKey2Hex & ")")
    let keys = requiredKeys(node)
    check keys.len == 2

  test "requiredKeys for or_i":
    let node = parseMiniscript("or_i(pk_k(" & TestKey1Hex & "),pk_k(" & TestKey2Hex & "))")
    let keys = requiredKeys(node)
    check keys.len == 2

  test "hasTimelockConflict returns false for no timelocks":
    let node = parseMiniscript("pk_k(" & TestKey1Hex & ")")
    check not hasTimelockConflict(node)

  test "hasTimelockConflict returns false for single timelock":
    let node = parseMiniscript("older(100)")
    check not hasTimelockConflict(node)

  test "hasTimelockConflict returns true for conflicting timelocks":
    # Mix height-based and time-based sequence locks
    let heightBased = "older(100)"
    let timeBased = "older(" & $(1'u32 shl 22 + 100) & ")"  # With type flag

    let node = parseMiniscript("and_v(v:" & heightBased & "," & timeBased & ")")
    check hasTimelockConflict(node)

# =============================================================================
# Roundtrip Tests
# =============================================================================

suite "miniscript roundtrip":
  test "parse and toString for pk_k":
    let original = "pk_k(" & TestKey1Hex & ")"
    let node = parseMiniscript(original)
    let result = toString(node)
    check result == original

  test "parse and toString for multi":
    let original = "multi(2," & TestKey1Hex & "," & TestKey2Hex & ")"
    let node = parseMiniscript(original)
    let result = toString(node)
    check result == original

  test "parse and toString for complex expression":
    let original = "and_v(v:pk_k(" & TestKey1Hex & "),pk_k(" & TestKey2Hex & "))"
    let node = parseMiniscript(original)
    let result = toString(node)
    check result == original

# =============================================================================
# Tapscript Tests
# =============================================================================

suite "miniscript tapscript":
  test "multi_a only in tapscript":
    expect(MiniscriptError):
      discard parseMiniscript("multi_a(2," & TestKey1Hex & "," & TestKey2Hex & ")", MsP2WSH)

    let node = parseMiniscript("multi_a(2," & TestKey1Hex & "," & TestKey2Hex & ")", MsTapscript)
    check node.kind == MsMultiA

  test "multi not in tapscript":
    expect(MiniscriptError):
      discard parseMiniscript("multi(2," & TestKey1Hex & "," & TestKey2Hex & ")", MsTapscript)

  test "compile multi_a":
    let node = parseMiniscript("multi_a(2," & TestKey1Hex & "," & TestKey2Hex & ")", MsTapscript)
    let script = compile(node, MsTapscript)
    check OP_CHECKSIG in script
    check OP_CHECKSIGADD in script
    check OP_NUMEQUAL in script

  test "satisfy multi_a":
    let node = parseMiniscript("multi_a(2," & TestKey1Hex & "," & TestKey2Hex & "," & TestKey3Hex & ")", MsTapscript)

    var sigCtx = SigningContext.new()
    sigCtx.availableKeys = initTable[PublicKey, seq[byte]]()
    sigCtx.availableKeys[key1] = @[0xAA'u8] & newSeq[byte](63)  # 64-byte Schnorr
    sigCtx.availableKeys[key2] = @[0xBB'u8] & newSeq[byte](63)

    let res = satisfy(node, sigCtx, MsTapscript)
    check res.sat.available == AvailYes
