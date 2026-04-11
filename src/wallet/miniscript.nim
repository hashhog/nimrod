## Miniscript: Structured Bitcoin Script representation
## A composable policy language with type checking and satisfaction analysis
##
## Reference: Bitcoin Core script/miniscript.cpp, BIP-379

import std/[strutils, options, tables, algorithm, sequtils]
import ../crypto/[hashing, secp256k1]
import ../script/interpreter

export secp256k1.PublicKey

type
  MiniscriptError* = object of CatchableError

  ## Miniscript context (affects available fragments and script limits)
  MsContext* = enum
    MsP2WSH    ## SegWit v0 (P2WSH)
    MsTapscript  ## SegWit v1 (Taproot tapscript)

  ## Basic types (B, V, K, W) - exactly one must be set
  ## See Bitcoin Core miniscript.h for detailed semantics
  MsBaseType* = enum
    MsTypeB  ## Base: consumes inputs, pushes nonzero on success, zero on failure
    MsTypeV  ## Verify: consumes inputs, no output, cannot fail (aborts)
    MsTypeK  ## Key: like B but always pushes a pubkey
    MsTypeW  ## Wrapped: like B but consumes one element from below top

  ## Type properties
  MsFlag* = enum
    mfZ  ## Zero-arg: consumes exactly 0 stack elements
    mfO  ## One-arg: consumes exactly 1 stack element
    mfN  ## Nonzero: satisfaction never needs zero top element
    mfD  ## Dissatisfiable: easy dissatisfaction exists
    mfU  ## Unit: pushes exactly 1 (not just nonzero)
    mfE  ## Expression: dissatisfaction is nonmalleable (implies d)
    mfF  ## Forced: dissatisfaction involves signature
    mfS  ## Safe: satisfaction involves signature
    mfM  ## Nonmalleable: nonmalleable satisfaction exists
    mfX  ## Expensive verify: last op is not EQUAL/CHECKSIG/CHECKMULTISIG
    mfK  ## No timelock conflicts in any satisfaction

  MsType* = object
    base*: MsBaseType
    flags*: set[MsFlag]

  ## Miniscript fragment kinds
  MsKind* = enum
    ## Leaves
    MsJust0         ## OP_0
    MsJust1         ## OP_1
    MsPkK           ## [key] - raw pubkey
    MsPkH           ## OP_DUP OP_HASH160 [keyhash] OP_EQUALVERIFY
    MsOlder         ## [n] OP_CHECKSEQUENCEVERIFY
    MsAfter         ## [n] OP_CHECKLOCKTIMEVERIFY
    MsSha256        ## OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 [hash] OP_EQUAL
    MsHash256       ## OP_SIZE 32 OP_EQUALVERIFY OP_HASH256 [hash] OP_EQUAL
    MsRipemd160     ## OP_SIZE 32 OP_EQUALVERIFY OP_RIPEMD160 [hash] OP_EQUAL
    MsHash160       ## OP_SIZE 32 OP_EQUALVERIFY OP_HASH160 [hash] OP_EQUAL

    # Wrappers - single child
    MsWrapA         ## a: OP_TOALTSTACK [X] OP_FROMALTSTACK
    MsWrapS         ## s: OP_SWAP [X]
    MsWrapC         ## c: [X] OP_CHECKSIG
    MsWrapD         ## d: OP_DUP OP_IF [X] OP_ENDIF
    MsWrapV         ## v: [X] OP_VERIFY (or merged -VERIFY)
    MsWrapJ         ## j: OP_SIZE OP_0NOTEQUAL OP_IF [X] OP_ENDIF
    MsWrapN         ## n: [X] OP_0NOTEQUAL

    # Combinators - two children
    MsAndV          ## and_v: [X] [Y]
    MsAndB          ## and_b: [X] [Y] OP_BOOLAND
    MsOrB           ## or_b: [X] [Y] OP_BOOLOR
    MsOrC           ## or_c: [X] OP_NOTIF [Y] OP_ENDIF
    MsOrD           ## or_d: [X] OP_IFDUP OP_NOTIF [Y] OP_ENDIF
    MsOrI           ## or_i: OP_IF [X] OP_ELSE [Y] OP_ENDIF
    MsAndOr         ## andor: [X] OP_NOTIF [Z] OP_ELSE [Y] OP_ENDIF

    # Multi
    MsThresh        ## thresh: [X1] ([Xn] OP_ADD)* [k] OP_EQUAL
    MsMulti         ## multi - P2WSH only
    MsMultiA        ## multi_a - Tapscript only

  ## Input availability for satisfaction
  Availability* = enum
    AvailNo     ## Not available
    AvailYes    ## Available
    AvailMaybe  ## May or may not be available

  ## Represents a single witness element in a satisfaction
  InputStack* = object
    available*: Availability
    hasSig*: bool       ## Contains at least one signature
    malleable*: bool    ## Can be modified by third party
    nonCanon*: bool     ## Not canonical form
    size*: int          ## Serialized witness size
    stack*: seq[seq[byte]]

  ## Result of satisfaction computation
  SatisfactionResult* = object
    sat*: InputStack    ## Satisfaction witness
    dissat*: InputStack ## Dissatisfaction witness

  ## Miniscript node
  MsNode* = ref object
    case kind*: MsKind
    of MsJust0, MsJust1:
      discard
    of MsPkK, MsPkH:
      key*: PublicKey
    of MsOlder, MsAfter:
      lockValue*: uint32
    of MsSha256, MsHash256:
      hash32*: array[32, byte]
    of MsRipemd160, MsHash160:
      hash20*: array[20, byte]
    of MsWrapA, MsWrapS, MsWrapC, MsWrapD, MsWrapV, MsWrapJ, MsWrapN:
      sub*: MsNode
    of MsAndV, MsAndB, MsOrB, MsOrC, MsOrD, MsOrI:
      left*: MsNode
      right*: MsNode
    of MsAndOr:
      x*: MsNode  ## Condition
      y*: MsNode  ## Then branch
      z*: MsNode  ## Else branch
    of MsThresh:
      threshold*: int
      subs*: seq[MsNode]
    of MsMulti, MsMultiA:
      k*: int
      keys*: seq[PublicKey]

    # Cached computed values
    msType*: MsType
    scriptLen*: int

  ## Signing context for satisfaction
  SigningContext* = ref object
    availableKeys*: Table[PublicKey, seq[byte]]  ## Key -> signature
    availablePreimages32*: Table[array[32, byte], seq[byte]]
    availablePreimages20*: Table[array[20, byte], seq[byte]]
    checkOlder*: proc(n: uint32): bool
    checkAfter*: proc(n: uint32): bool

# =============================================================================
# Helpers
# =============================================================================

proc bytesToHex(data: openArray[byte]): string =
  ## Convert bytes to hex string
  result = newString(data.len * 2)
  const hexChars = "0123456789abcdef"
  for i, b in data:
    result[i*2] = hexChars[int(b shr 4)]
    result[i*2+1] = hexChars[int(b and 0x0f)]

# =============================================================================
# Constants
# =============================================================================

const
  MaxMultiKeys* = 20        ## Max keys in P2WSH multi
  MaxMultiAKeys* = 999      ## Max keys in tapscript multi_a
  MaxStandardP2WSHScriptSize* = 3600

  ## Timelock type flags (from BIP 68)
  SequenceLocktimeTypeFlag* = 1'u32 shl 22

  ## Locktime threshold (500M for block time vs height)
  LocktimeThreshold* = 500_000_000'u32

# =============================================================================
# InputStack Operations
# =============================================================================

proc newInputStack*(): InputStack =
  ## Empty input stack (EMPTY in Bitcoin Core)
  InputStack(available: AvailYes, size: 0)

proc newInputStackZero*(): InputStack =
  ## Single zero element (ZERO in Bitcoin Core)
  InputStack(available: AvailYes, size: 1, stack: @[@[0'u8]])

proc newInputStackOne*(): InputStack =
  ## Single one element
  InputStack(available: AvailYes, size: 1, stack: @[@[1'u8]])

proc newInputStack*(data: seq[byte]): InputStack =
  ## Stack with single element
  InputStack(available: AvailYes, size: data.len + 1, stack: @[data])  # +1 for push opcode

proc setWithSig*(s: var InputStack): InputStack =
  s.hasSig = true
  s

proc setAvailable*(s: var InputStack, avail: Availability): InputStack =
  s.available = avail
  s

proc setMalleable*(s: var InputStack): InputStack =
  s.malleable = true
  s

proc `+`*(a, b: InputStack): InputStack =
  ## Concatenate two input stacks
  if a.available == AvailNo or b.available == AvailNo:
    return InputStack(available: AvailNo)

  result.available = if a.available == AvailYes and b.available == AvailYes:
    AvailYes
  else:
    AvailMaybe
  result.hasSig = a.hasSig or b.hasSig
  result.malleable = a.malleable or b.malleable
  result.nonCanon = a.nonCanon or b.nonCanon
  result.size = a.size + b.size
  result.stack = a.stack & b.stack

proc `|`*(a, b: InputStack): InputStack =
  ## Choose best of two alternatives
  ## Priority: available > has_sig > non-malleable > smaller size
  if a.available == AvailNo:
    return b
  if b.available == AvailNo:
    return a

  # Both available
  let aScore = (if a.hasSig: 4 else: 0) +
               (if not a.malleable: 2 else: 0) +
               (if not a.nonCanon: 1 else: 0)
  let bScore = (if b.hasSig: 4 else: 0) +
               (if not b.malleable: 2 else: 0) +
               (if not b.nonCanon: 1 else: 0)

  if aScore > bScore:
    return a
  if bScore > aScore:
    return b

  # Equal score, pick smaller
  if a.size <= b.size:
    return a
  return b

# =============================================================================
# Type System
# =============================================================================

proc newMsType*(base: MsBaseType, flags: set[MsFlag] = {}): MsType =
  MsType(base: base, flags: flags)

proc `<<`*(a, b: MsType): bool =
  ## Check if type a is subtype of b (a has all properties of b)
  a.base == b.base and b.flags <= a.flags

proc hasFlag*(t: MsType, f: MsFlag): bool =
  f in t.flags

proc hasZ*(t: MsType): bool = mfZ in t.flags
proc hasO*(t: MsType): bool = mfO in t.flags
proc hasN*(t: MsType): bool = mfN in t.flags
proc hasD*(t: MsType): bool = mfD in t.flags
proc hasU*(t: MsType): bool = mfU in t.flags
proc hasE*(t: MsType): bool = mfE in t.flags
proc hasF*(t: MsType): bool = mfF in t.flags
proc hasS*(t: MsType): bool = mfS in t.flags
proc hasM*(t: MsType): bool = mfM in t.flags
proc hasX*(t: MsType): bool = mfX in t.flags
proc hasK*(t: MsType): bool = mfK in t.flags

proc isB*(t: MsType): bool = t.base == MsTypeB
proc isV*(t: MsType): bool = t.base == MsTypeV
proc isK*(t: MsType): bool = t.base == MsTypeK
proc isW*(t: MsType): bool = t.base == MsTypeW

proc computeType*(node: MsNode, ctx: MsContext): MsType =
  ## Compute the type of a miniscript node
  let isTapscript = ctx == MsTapscript

  case node.kind
  of MsJust0:
    # 0 has type Bzudemsxk
    result = newMsType(MsTypeB, {mfZ, mfU, mfD, mfE, mfM, mfS, mfX, mfK})

  of MsJust1:
    # 1 has type Bzufmxk
    result = newMsType(MsTypeB, {mfZ, mfU, mfF, mfM, mfX, mfK})

  of MsPkK:
    # pk_k(key) has type Konudemsxk
    result = newMsType(MsTypeK, {mfO, mfN, mfU, mfD, mfE, mfM, mfS, mfX, mfK})

  of MsPkH:
    # pk_h(key) has type Knudemsxk
    result = newMsType(MsTypeK, {mfN, mfU, mfD, mfE, mfM, mfS, mfX, mfK})

  of MsOlder:
    # older(n) has type Bzfmxk + g/h depending on time/height
    let isTime = (node.lockValue and SequenceLocktimeTypeFlag) != 0
    var flags = {mfZ, mfF, mfM, mfX, mfK}
    # Note: g/h flags for timelock tracking not included in MsFlag set
    result = newMsType(MsTypeB, flags)

  of MsAfter:
    # after(n) has type Bzfmxk + i/j depending on time/height
    let isTime = node.lockValue >= LocktimeThreshold
    var flags = {mfZ, mfF, mfM, mfX, mfK}
    result = newMsType(MsTypeB, flags)

  of MsSha256, MsHash256, MsRipemd160, MsHash160:
    # hash checks have type Bonudmk
    result = newMsType(MsTypeB, {mfO, mfN, mfU, mfD, mfM, mfK})

  of MsWrapA:
    # a:X - converts B to W
    let subType = computeType(node.sub, ctx)
    if subType.base != MsTypeB:
      raise newException(MiniscriptError, "a: wrapper requires B type")
    result = newMsType(MsTypeW, subType.flags)

  of MsWrapS:
    # s:X - converts Bo to W
    let subType = computeType(node.sub, ctx)
    if subType.base != MsTypeB or not subType.hasO:
      raise newException(MiniscriptError, "s: wrapper requires Bo type")
    result = newMsType(MsTypeW, subType.flags)

  of MsWrapC:
    # c:X - converts K to B, adds us
    let subType = computeType(node.sub, ctx)
    if subType.base != MsTypeK:
      raise newException(MiniscriptError, "c: wrapper requires K type")
    result = newMsType(MsTypeB, subType.flags + {mfU, mfS})

  of MsWrapD:
    # d:X - converts Vz to B, adds ondxu (u only in tapscript)
    let subType = computeType(node.sub, ctx)
    if subType.base != MsTypeV or not subType.hasZ:
      raise newException(MiniscriptError, "d: wrapper requires Vz type")
    var flags = subType.flags + {mfO, mfN, mfD, mfX}
    if isTapscript:
      flags.incl(mfU)
    result = newMsType(MsTypeB, flags)

  of MsWrapV:
    # v:X - converts B to V, adds fx
    let subType = computeType(node.sub, ctx)
    if subType.base != MsTypeB:
      raise newException(MiniscriptError, "v: wrapper requires B type")
    result = newMsType(MsTypeV, (subType.flags - {mfD, mfU, mfE}) + {mfF, mfX})

  of MsWrapJ:
    # j:X - converts Bn to B, adds ndx
    let subType = computeType(node.sub, ctx)
    if subType.base != MsTypeB or not subType.hasN:
      raise newException(MiniscriptError, "j: wrapper requires Bn type")
    result = newMsType(MsTypeB, subType.flags + {mfN, mfD, mfX})

  of MsWrapN:
    # n:X - converts B to B, adds ux
    let subType = computeType(node.sub, ctx)
    if subType.base != MsTypeB:
      raise newException(MiniscriptError, "n: wrapper requires B type")
    result = newMsType(MsTypeB, subType.flags + {mfU, mfX})

  of MsAndV:
    # and_v(X,Y) - requires X:V
    let xType = computeType(node.left, ctx)
    let yType = computeType(node.right, ctx)
    if xType.base != MsTypeV:
      raise newException(MiniscriptError, "and_v requires V type for first argument")

    # Result type is Y's base type
    var flags: set[MsFlag]

    # n from X or (n from Y if X is z)
    if xType.hasN or (yType.hasN and xType.hasZ):
      flags.incl(mfN)

    # o if one is z
    if (xType.hasO or yType.hasO) and (xType.hasZ or yType.hasZ):
      flags.incl(mfO)

    # z requires both
    if xType.hasZ and yType.hasZ:
      flags.incl(mfZ)

    # m requires both
    if xType.hasM and yType.hasM:
      flags.incl(mfM)

    # s from either
    if xType.hasS or yType.hasS:
      flags.incl(mfS)

    # f from Y or s from X
    if yType.hasF or xType.hasS:
      flags.incl(mfF)

    # u and x from Y
    if yType.hasU:
      flags.incl(mfU)
    if yType.hasX:
      flags.incl(mfX)

    # k requires both have k and no timelock conflicts
    if xType.hasK and yType.hasK:
      flags.incl(mfK)

    result = newMsType(yType.base, flags)

  of MsAndB:
    # and_b(X,Y) - X:B, Y:W
    let xType = computeType(node.left, ctx)
    let yType = computeType(node.right, ctx)
    if xType.base != MsTypeB or yType.base != MsTypeW:
      raise newException(MiniscriptError, "and_b requires B and W types")

    var flags: set[MsFlag]

    # n if both have n
    if xType.hasN and yType.hasN:
      flags.incl(mfN)

    # z if both have z
    if xType.hasZ and yType.hasZ:
      flags.incl(mfZ)

    # o if both have o
    if xType.hasO and yType.hasO:
      flags.incl(mfO)

    # d if both have d
    if xType.hasD and yType.hasD:
      flags.incl(mfD)

    # u always (BOOLAND pushes 0 or 1)
    flags.incl(mfU)

    # e if both have e and one doesn't have f
    if xType.hasE and yType.hasE:
      if not (xType.hasF and yType.hasF):
        flags.incl(mfE)

    # m if both have m and e
    if xType.hasM and yType.hasM:
      if mfE in flags:
        flags.incl(mfM)

    # s from either
    if xType.hasS or yType.hasS:
      flags.incl(mfS)

    # x always (BOOLAND)
    flags.incl(mfX)

    # k if both
    if xType.hasK and yType.hasK:
      flags.incl(mfK)

    result = newMsType(MsTypeB, flags)

  of MsOrB:
    # or_b(X,Y) - X:Bd, Y:Wd
    let xType = computeType(node.left, ctx)
    let yType = computeType(node.right, ctx)
    if xType.base != MsTypeB or not xType.hasD:
      raise newException(MiniscriptError, "or_b first arg requires Bd type")
    if yType.base != MsTypeW or not yType.hasD:
      raise newException(MiniscriptError, "or_b second arg requires Wd type")

    var flags: set[MsFlag]

    # z if both z
    if xType.hasZ and yType.hasZ:
      flags.incl(mfZ)

    # o if both z or o (and one z)
    if (xType.hasZ or xType.hasO) and (yType.hasZ or yType.hasO):
      if xType.hasZ or yType.hasZ:
        flags.incl(mfO)

    # d always
    flags.incl(mfD)

    # u always
    flags.incl(mfU)

    # e if both e
    if xType.hasE and yType.hasE:
      flags.incl(mfE)

    # m if both m and both e
    if xType.hasM and yType.hasM and mfE in flags:
      flags.incl(mfM)

    # s if both s
    if xType.hasS and yType.hasS:
      flags.incl(mfS)

    flags.incl(mfX)

    if xType.hasK and yType.hasK:
      flags.incl(mfK)

    result = newMsType(MsTypeB, flags)

  of MsOrC:
    # or_c(X,Y) - X:Bdu, Y:V
    let xType = computeType(node.left, ctx)
    let yType = computeType(node.right, ctx)
    if xType.base != MsTypeB or not xType.hasD or not xType.hasU:
      raise newException(MiniscriptError, "or_c first arg requires Bdu type")
    if yType.base != MsTypeV:
      raise newException(MiniscriptError, "or_c second arg requires V type")

    var flags: set[MsFlag]

    # z if both z
    if xType.hasZ and yType.hasZ:
      flags.incl(mfZ)

    # o if one z
    if xType.hasZ or yType.hasZ:
      if xType.hasO or yType.hasO:
        flags.incl(mfO)

    # f always (Y is V which is f)
    flags.incl(mfF)

    # m if both m and x has e
    if xType.hasM and yType.hasM and xType.hasE:
      flags.incl(mfM)

    # s from either
    if xType.hasS or yType.hasS:
      flags.incl(mfS)

    flags.incl(mfX)

    if xType.hasK and yType.hasK:
      flags.incl(mfK)

    result = newMsType(MsTypeV, flags)

  of MsOrD:
    # or_d(X,Y) - X:Bdu, Y:B
    let xType = computeType(node.left, ctx)
    let yType = computeType(node.right, ctx)
    if xType.base != MsTypeB or not xType.hasD or not xType.hasU:
      raise newException(MiniscriptError, "or_d first arg requires Bdu type")
    if yType.base != MsTypeB:
      raise newException(MiniscriptError, "or_d second arg requires B type")

    var flags: set[MsFlag]

    # z if both z
    if xType.hasZ and yType.hasZ:
      flags.incl(mfZ)

    # o if one z
    if xType.hasZ or yType.hasZ:
      if xType.hasO or yType.hasO:
        flags.incl(mfO)

    # d from Y
    if yType.hasD:
      flags.incl(mfD)

    # u from Y
    if yType.hasU:
      flags.incl(mfU)

    # e from Y if X has e
    if xType.hasE and yType.hasE:
      flags.incl(mfE)

    # m if both m and x has e
    if xType.hasM and yType.hasM and xType.hasE:
      flags.incl(mfM)

    # s from either
    if xType.hasS or yType.hasS:
      flags.incl(mfS)

    flags.incl(mfX)

    if xType.hasK and yType.hasK:
      flags.incl(mfK)

    result = newMsType(MsTypeB, flags)

  of MsOrI:
    # or_i(X,Y) - both must be same base type (B or V)
    let xType = computeType(node.left, ctx)
    let yType = computeType(node.right, ctx)
    if xType.base != yType.base:
      raise newException(MiniscriptError, "or_i requires same base types")
    if xType.base != MsTypeB and xType.base != MsTypeV:
      raise newException(MiniscriptError, "or_i requires B or V types")

    var flags: set[MsFlag]

    # o from either having z
    if xType.hasZ or yType.hasZ:
      flags.incl(mfO)

    # d from either
    if xType.hasD or yType.hasD:
      flags.incl(mfD)

    # u from both
    if xType.hasU and yType.hasU:
      flags.incl(mfU)

    # e if both have e and one has f
    if xType.hasE and yType.hasE:
      if xType.hasF or yType.hasF:
        flags.incl(mfE)

    # f from both
    if xType.hasF and yType.hasF:
      flags.incl(mfF)

    # m if both m and e
    if xType.hasM and yType.hasM and mfE in flags:
      flags.incl(mfM)

    # s from either
    if xType.hasS or yType.hasS:
      flags.incl(mfS)

    flags.incl(mfX)

    if xType.hasK and yType.hasK:
      flags.incl(mfK)

    result = newMsType(xType.base, flags)

  of MsAndOr:
    # andor(X,Y,Z) - X:Bdu, Y and Z same base
    let xType = computeType(node.x, ctx)
    let yType = computeType(node.y, ctx)
    let zType = computeType(node.z, ctx)

    if xType.base != MsTypeB or not xType.hasD or not xType.hasU:
      raise newException(MiniscriptError, "andor first arg requires Bdu type")
    if yType.base != zType.base:
      raise newException(MiniscriptError, "andor requires same base types for Y and Z")
    if yType.base != MsTypeB and yType.base != MsTypeV:
      raise newException(MiniscriptError, "andor requires B or V types for Y and Z")

    var flags: set[MsFlag]

    # z if all z
    if xType.hasZ and yType.hasZ and zType.hasZ:
      flags.incl(mfZ)

    # o: complex rules
    let zo = (if xType.hasZ: 1 else: 0) + (if yType.hasZ: 1 else: 0) + (if zType.hasZ: 1 else: 0)
    if zo >= 2:
      if xType.hasO or yType.hasO or zType.hasO:
        flags.incl(mfO)

    # d from Z
    if zType.hasD:
      flags.incl(mfD)

    # u from both Y and Z
    if yType.hasU and zType.hasU:
      flags.incl(mfU)

    # f from X and (Y or Z)
    if xType.hasF and (yType.hasF or zType.hasF):
      flags.incl(mfF)
    elif yType.hasF and zType.hasF:
      flags.incl(mfF)

    # s from either
    if xType.hasS or yType.hasS or zType.hasS:
      flags.incl(mfS)

    flags.incl(mfX)

    if xType.hasK and yType.hasK and zType.hasK:
      flags.incl(mfK)

    result = newMsType(yType.base, flags)

  of MsThresh:
    # thresh(k, X1, ..., Xn) - all must be Bdu except last can be Bu
    if node.subs.len == 0:
      raise newException(MiniscriptError, "thresh requires at least one argument")

    var allZ = true
    var allM = true
    var allE = true
    var anyS = false
    var allK = true

    for i, sub in node.subs:
      let subType = computeType(sub, ctx)
      if subType.base != MsTypeB:
        raise newException(MiniscriptError, "thresh requires B types")
      if i < node.subs.len - 1:
        if not subType.hasD or not subType.hasU:
          raise newException(MiniscriptError, "thresh non-final args require Bdu")
      else:
        if not subType.hasU:
          raise newException(MiniscriptError, "thresh final arg requires Bu")

      if not subType.hasZ: allZ = false
      if not subType.hasM: allM = false
      if not subType.hasE: allE = false
      if subType.hasS: anyS = true
      if not subType.hasK: allK = false

    var flags: set[MsFlag]
    if allZ: flags.incl(mfZ)
    flags.incl(mfD)
    flags.incl(mfU)
    if anyS: flags.incl(mfS)
    if allE: flags.incl(mfE)
    if allM and allE:
      flags.incl(mfM)
    flags.incl(mfX)
    if allK: flags.incl(mfK)

    result = newMsType(MsTypeB, flags)

  of MsMulti:
    # multi(k, key1, ..., keyn) - P2WSH only
    if isTapscript:
      raise newException(MiniscriptError, "multi not allowed in tapscript, use multi_a")

    # Type: Bnudemsk
    result = newMsType(MsTypeB, {mfN, mfU, mfD, mfE, mfM, mfS, mfK})

  of MsMultiA:
    # multi_a(k, key1, ..., keyn) - Tapscript only
    if not isTapscript:
      raise newException(MiniscriptError, "multi_a only allowed in tapscript")

    # Type: Budemsk (note: no 'n' unlike multi)
    result = newMsType(MsTypeB, {mfU, mfD, mfE, mfM, mfS, mfK})

proc validateType*(node: MsNode, ctx: MsContext): bool =
  ## Validate that a miniscript has correct types
  try:
    discard computeType(node, ctx)
    return true
  except MiniscriptError:
    return false

# =============================================================================
# Script Compilation
# =============================================================================

proc pushData(script: var seq[byte], data: openArray[byte]) =
  ## Push data with minimal encoding
  let n = data.len
  if n == 0:
    script.add(OP_0)
  elif n <= 75:
    script.add(byte(n))
    script.add(@data)
  elif n <= 255:
    script.add(OP_PUSHDATA1)
    script.add(byte(n))
    script.add(@data)
  elif n <= 65535:
    script.add(OP_PUSHDATA2)
    script.add(byte(n and 0xFF))
    script.add(byte((n shr 8) and 0xFF))
    script.add(@data)
  else:
    script.add(OP_PUSHDATA4)
    script.add(byte(n and 0xFF))
    script.add(byte((n shr 8) and 0xFF))
    script.add(byte((n shr 16) and 0xFF))
    script.add(byte((n shr 24) and 0xFF))
    script.add(@data)

proc pushNumber(script: var seq[byte], n: int64) =
  ## Push a number using minimal encoding
  if n == 0:
    script.add(OP_0)
  elif n >= 1 and n <= 16:
    script.add(byte(0x50 + n))  # OP_1 through OP_16
  elif n == -1:
    script.add(OP_1NEGATE)
  else:
    # CScriptNum encoding
    var value = if n < 0: -n else: n
    var data: seq[byte]
    while value > 0:
      data.add(byte(value and 0xFF))
      value = value shr 8

    # Add sign bit if needed
    if (data[^1] and 0x80) != 0:
      data.add(if n < 0: 0x80'u8 else: 0x00'u8)
    elif n < 0:
      data[^1] = data[^1] or 0x80

    script.pushData(data)

proc compileImpl(node: MsNode, ctx: MsContext, verify: bool): seq[byte]

proc compile*(node: MsNode, ctx: MsContext = MsP2WSH): seq[byte] =
  ## Compile miniscript to Bitcoin Script bytes
  compileImpl(node, ctx, false)

proc compileImpl(node: MsNode, ctx: MsContext, verify: bool): seq[byte] =
  let isTapscript = ctx == MsTapscript

  case node.kind
  of MsJust0:
    result.add(OP_0)

  of MsJust1:
    result.add(OP_1)

  of MsPkK:
    # Push pubkey (33 bytes compressed, 32 bytes x-only for tapscript)
    if isTapscript:
      # X-only pubkey
      var xonly: array[32, byte]
      copyMem(addr xonly[0], addr node.key[1], 32)
      result.pushData(xonly)
    else:
      result.pushData(node.key)

  of MsPkH:
    # OP_DUP OP_HASH160 <keyhash> OP_EQUALVERIFY
    let keyhash = hash160(node.key)
    result.add(OP_DUP)
    result.add(OP_HASH160)
    result.pushData(keyhash)
    result.add(OP_EQUALVERIFY)

  of MsOlder:
    result.pushNumber(int64(node.lockValue))
    result.add(OP_CHECKSEQUENCEVERIFY)

  of MsAfter:
    result.pushNumber(int64(node.lockValue))
    result.add(OP_CHECKLOCKTIMEVERIFY)

  of MsSha256:
    # OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUAL
    result.add(OP_SIZE)
    result.pushNumber(32)
    result.add(OP_EQUALVERIFY)
    result.add(OP_SHA256)
    result.pushData(node.hash32)
    if verify:
      result.add(OP_EQUALVERIFY)
    else:
      result.add(OP_EQUAL)

  of MsHash256:
    result.add(OP_SIZE)
    result.pushNumber(32)
    result.add(OP_EQUALVERIFY)
    result.add(OP_HASH256)
    result.pushData(node.hash32)
    if verify:
      result.add(OP_EQUALVERIFY)
    else:
      result.add(OP_EQUAL)

  of MsRipemd160:
    result.add(OP_SIZE)
    result.pushNumber(32)
    result.add(OP_EQUALVERIFY)
    result.add(OP_RIPEMD160)
    result.pushData(node.hash20)
    if verify:
      result.add(OP_EQUALVERIFY)
    else:
      result.add(OP_EQUAL)

  of MsHash160:
    result.add(OP_SIZE)
    result.pushNumber(32)
    result.add(OP_EQUALVERIFY)
    result.add(OP_HASH160)
    result.pushData(node.hash20)
    if verify:
      result.add(OP_EQUALVERIFY)
    else:
      result.add(OP_EQUAL)

  of MsWrapA:
    # OP_TOALTSTACK [X] OP_FROMALTSTACK
    result.add(OP_TOALTSTACK)
    result.add(compileImpl(node.sub, ctx, false))
    result.add(OP_FROMALTSTACK)

  of MsWrapS:
    # OP_SWAP [X]
    result.add(OP_SWAP)
    result.add(compileImpl(node.sub, ctx, verify))

  of MsWrapC:
    # [X] OP_CHECKSIG(VERIFY)
    result.add(compileImpl(node.sub, ctx, false))
    if verify:
      result.add(OP_CHECKSIGVERIFY)
    else:
      result.add(OP_CHECKSIG)

  of MsWrapD:
    # OP_DUP OP_IF [X] OP_ENDIF
    result.add(OP_DUP)
    result.add(OP_IF)
    result.add(compileImpl(node.sub, ctx, false))
    result.add(OP_ENDIF)

  of MsWrapV:
    # [X] OP_VERIFY (or use *VERIFY opcode)
    let subType = computeType(node.sub, ctx)
    let subScript = compileImpl(node.sub, ctx, true)

    # Check if we can merge VERIFY with last opcode
    if subScript.len > 0:
      let lastOp = subScript[^1]
      if lastOp == OP_CHECKSIG:
        result.add(subScript[0 ..< ^1])
        result.add(OP_CHECKSIGVERIFY)
        return
      elif lastOp == OP_EQUAL:
        result.add(subScript[0 ..< ^1])
        result.add(OP_EQUALVERIFY)
        return
      elif lastOp == OP_NUMEQUAL:
        result.add(subScript[0 ..< ^1])
        result.add(OP_NUMEQUALVERIFY)
        return
      elif lastOp == OP_CHECKMULTISIG:
        result.add(subScript[0 ..< ^1])
        result.add(OP_CHECKMULTISIGVERIFY)
        return

    # Otherwise add explicit VERIFY
    result.add(subScript)
    # Only add OP_VERIFY if not already in verify mode AND subScript doesn't
    # already end with a *VERIFY opcode (which happens when sub compiled with verify=true)
    let alreadyVerified = subScript.len > 0 and subScript[^1] in [
      OP_CHECKSIGVERIFY, OP_EQUALVERIFY, OP_NUMEQUALVERIFY, OP_CHECKMULTISIGVERIFY]
    if not verify and not alreadyVerified:
      result.add(OP_VERIFY)

  of MsWrapJ:
    # OP_SIZE OP_0NOTEQUAL OP_IF [X] OP_ENDIF
    result.add(OP_SIZE)
    result.add(OP_0NOTEQUAL)
    result.add(OP_IF)
    result.add(compileImpl(node.sub, ctx, false))
    result.add(OP_ENDIF)

  of MsWrapN:
    # [X] OP_0NOTEQUAL
    result.add(compileImpl(node.sub, ctx, false))
    result.add(OP_0NOTEQUAL)

  of MsAndV:
    # [X] [Y]
    result.add(compileImpl(node.left, ctx, false))
    result.add(compileImpl(node.right, ctx, verify))

  of MsAndB:
    # [X] [Y] OP_BOOLAND
    result.add(compileImpl(node.left, ctx, false))
    result.add(compileImpl(node.right, ctx, false))
    if verify:
      # BOOLAND then VERIFY
      result.add(OP_BOOLAND)
      result.add(OP_VERIFY)
    else:
      result.add(OP_BOOLAND)

  of MsOrB:
    # [X] [Y] OP_BOOLOR
    result.add(compileImpl(node.left, ctx, false))
    result.add(compileImpl(node.right, ctx, false))
    if verify:
      result.add(OP_BOOLOR)
      result.add(OP_VERIFY)
    else:
      result.add(OP_BOOLOR)

  of MsOrC:
    # [X] OP_NOTIF [Y] OP_ENDIF
    result.add(compileImpl(node.left, ctx, false))
    result.add(OP_NOTIF)
    result.add(compileImpl(node.right, ctx, false))
    result.add(OP_ENDIF)

  of MsOrD:
    # [X] OP_IFDUP OP_NOTIF [Y] OP_ENDIF
    result.add(compileImpl(node.left, ctx, false))
    result.add(OP_IFDUP)
    result.add(OP_NOTIF)
    result.add(compileImpl(node.right, ctx, verify))
    result.add(OP_ENDIF)

  of MsOrI:
    # OP_IF [X] OP_ELSE [Y] OP_ENDIF
    result.add(OP_IF)
    result.add(compileImpl(node.left, ctx, verify))
    result.add(OP_ELSE)
    result.add(compileImpl(node.right, ctx, verify))
    result.add(OP_ENDIF)

  of MsAndOr:
    # [X] OP_NOTIF [Z] OP_ELSE [Y] OP_ENDIF
    result.add(compileImpl(node.x, ctx, false))
    result.add(OP_NOTIF)
    result.add(compileImpl(node.z, ctx, verify))
    result.add(OP_ELSE)
    result.add(compileImpl(node.y, ctx, verify))
    result.add(OP_ENDIF)

  of MsThresh:
    # [X1] ([Xn] OP_ADD)* [k] OP_EQUAL
    for i, sub in node.subs:
      result.add(compileImpl(sub, ctx, false))
      if i > 0:
        result.add(OP_ADD)
    result.pushNumber(int64(node.threshold))
    if verify:
      result.add(OP_EQUALVERIFY)
    else:
      result.add(OP_EQUAL)

  of MsMulti:
    # [k] [key_n]* [n] OP_CHECKMULTISIG
    result.pushNumber(int64(node.k))
    for key in node.keys:
      result.pushData(key)
    result.pushNumber(int64(node.keys.len))
    if verify:
      result.add(OP_CHECKMULTISIGVERIFY)
    else:
      result.add(OP_CHECKMULTISIG)

  of MsMultiA:
    # [key_0] OP_CHECKSIG ([key_n] OP_CHECKSIGADD)* [k] OP_NUMEQUAL
    for i, key in node.keys:
      var xonly: array[32, byte]
      copyMem(addr xonly[0], addr key[1], 32)
      result.pushData(xonly)
      if i == 0:
        result.add(OP_CHECKSIG)
      else:
        result.add(OP_CHECKSIGADD)
    result.pushNumber(int64(node.k))
    if verify:
      result.add(OP_NUMEQUALVERIFY)
    else:
      result.add(OP_NUMEQUAL)

# =============================================================================
# Satisfaction
# =============================================================================

proc satisfy*(node: MsNode, ctx: SigningContext, msCtx: MsContext = MsP2WSH): SatisfactionResult

proc satisfyImpl(node: MsNode, ctx: SigningContext, msCtx: MsContext): SatisfactionResult =
  let isTapscript = msCtx == MsTapscript

  case node.kind
  of MsJust0:
    # 0 is always dissatisfied, never satisfied
    result.dissat = newInputStack()
    result.sat = InputStack(available: AvailNo)

  of MsJust1:
    # 1 is always satisfied, cannot be dissatisfied
    result.sat = newInputStack()
    result.dissat = InputStack(available: AvailNo)

  of MsPkK:
    # Satisfaction: signature
    # Dissatisfaction: empty
    result.dissat = newInputStackZero()

    if ctx.availableKeys.hasKey(node.key):
      var sig = ctx.availableKeys[node.key]
      result.sat = newInputStack(sig)
      result.sat.hasSig = true
    else:
      result.sat = InputStack(available: AvailNo)

  of MsPkH:
    # Satisfaction: <sig> <pubkey>
    # Dissatisfaction: <0> <pubkey>
    let pubkeyStack = newInputStack(@(node.key))
    result.dissat = newInputStackZero() + pubkeyStack

    if ctx.availableKeys.hasKey(node.key):
      var sig = ctx.availableKeys[node.key]
      var sat = newInputStack(sig)
      sat.hasSig = true
      result.sat = sat + pubkeyStack
    else:
      result.sat = InputStack(available: AvailNo)

  of MsOlder:
    # Satisfaction: (empty, timelock checked)
    # Dissatisfaction: impossible
    result.dissat = InputStack(available: AvailNo)

    if ctx.checkOlder != nil and ctx.checkOlder(node.lockValue):
      result.sat = newInputStack()
    else:
      result.sat = InputStack(available: AvailNo)

  of MsAfter:
    result.dissat = InputStack(available: AvailNo)

    if ctx.checkAfter != nil and ctx.checkAfter(node.lockValue):
      result.sat = newInputStack()
    else:
      result.sat = InputStack(available: AvailNo)

  of MsSha256:
    result.dissat = newInputStackZero()

    if ctx.availablePreimages32.hasKey(node.hash32):
      let preimage = ctx.availablePreimages32[node.hash32]
      result.sat = newInputStack(preimage)
    else:
      result.sat = InputStack(available: AvailNo)

  of MsHash256:
    result.dissat = newInputStackZero()

    # Hash256 is SHA256d
    let target = node.hash32
    for preimage, data in ctx.availablePreimages32:
      let computed = sha256d(data)
      if computed == target:
        result.sat = newInputStack(data)
        return
    result.sat = InputStack(available: AvailNo)

  of MsRipemd160:
    result.dissat = newInputStackZero()

    if ctx.availablePreimages20.hasKey(node.hash20):
      let preimage = ctx.availablePreimages20[node.hash20]
      result.sat = newInputStack(preimage)
    else:
      result.sat = InputStack(available: AvailNo)

  of MsHash160:
    result.dissat = newInputStackZero()

    if ctx.availablePreimages20.hasKey(node.hash20):
      let preimage = ctx.availablePreimages20[node.hash20]
      result.sat = newInputStack(preimage)
    else:
      result.sat = InputStack(available: AvailNo)

  of MsWrapA:
    # a:X - same satisfaction as X
    let sub = satisfyImpl(node.sub, ctx, msCtx)
    result = sub

  of MsWrapS:
    # s:X - same satisfaction as X
    let sub = satisfyImpl(node.sub, ctx, msCtx)
    result = sub

  of MsWrapC:
    # c:X - signature check
    let sub = satisfyImpl(node.sub, ctx, msCtx)
    result.sat = sub.sat
    result.dissat = sub.dissat

  of MsWrapD:
    # d:X - dissatisfy with 0
    let sub = satisfyImpl(node.sub, ctx, msCtx)
    result.sat = newInputStackOne() + sub.sat
    result.dissat = newInputStackZero()

  of MsWrapV:
    # v:X - no dissatisfaction
    let sub = satisfyImpl(node.sub, ctx, msCtx)
    result.sat = sub.sat
    result.dissat = InputStack(available: AvailNo)

  of MsWrapJ:
    # j:X - dissatisfy with 0
    let sub = satisfyImpl(node.sub, ctx, msCtx)
    result.sat = sub.sat
    result.dissat = newInputStackZero()

  of MsWrapN:
    # n:X - same as X
    let sub = satisfyImpl(node.sub, ctx, msCtx)
    result = sub

  of MsAndV:
    # and_v(X,Y) - need both satisfied
    let xRes = satisfyImpl(node.left, ctx, msCtx)
    let yRes = satisfyImpl(node.right, ctx, msCtx)
    result.sat = yRes.sat + xRes.sat
    result.dissat = InputStack(available: AvailNo)  # V cannot be dissatisfied

  of MsAndB:
    # and_b(X,Y) - need both satisfied
    let xRes = satisfyImpl(node.left, ctx, msCtx)
    let yRes = satisfyImpl(node.right, ctx, msCtx)
    result.sat = yRes.sat + xRes.sat
    result.dissat = yRes.dissat + xRes.dissat

  of MsOrB:
    # or_b(X,Y) - satisfy either
    let xRes = satisfyImpl(node.left, ctx, msCtx)
    let yRes = satisfyImpl(node.right, ctx, msCtx)

    # Choose best satisfaction
    let satX = yRes.dissat + xRes.sat
    let satY = yRes.sat + xRes.dissat
    result.sat = satX | satY
    result.dissat = yRes.dissat + xRes.dissat

  of MsOrC:
    # or_c(X,Y) - satisfy X or Y (Y is V)
    let xRes = satisfyImpl(node.left, ctx, msCtx)
    let yRes = satisfyImpl(node.right, ctx, msCtx)
    result.sat = xRes.sat | (yRes.sat + xRes.dissat)
    result.dissat = InputStack(available: AvailNo)

  of MsOrD:
    # or_d(X,Y) - satisfy X or Y
    let xRes = satisfyImpl(node.left, ctx, msCtx)
    let yRes = satisfyImpl(node.right, ctx, msCtx)
    result.sat = xRes.sat | (yRes.sat + xRes.dissat)
    result.dissat = yRes.dissat + xRes.dissat

  of MsOrI:
    # or_i(X,Y) - satisfy X (with 1) or Y (with 0)
    let xRes = satisfyImpl(node.left, ctx, msCtx)
    let yRes = satisfyImpl(node.right, ctx, msCtx)

    let satX = xRes.sat + newInputStackOne()
    let satY = yRes.sat + newInputStackZero()
    result.sat = satX | satY

    let dissatX = xRes.dissat + newInputStackOne()
    let dissatY = yRes.dissat + newInputStackZero()
    result.dissat = dissatX | dissatY

  of MsAndOr:
    # andor(X,Y,Z) - (X and Y) or Z
    let xRes = satisfyImpl(node.x, ctx, msCtx)
    let yRes = satisfyImpl(node.y, ctx, msCtx)
    let zRes = satisfyImpl(node.z, ctx, msCtx)

    let satXY = yRes.sat + xRes.sat
    let satZ = zRes.sat + xRes.dissat
    result.sat = satXY | satZ
    result.dissat = zRes.dissat + xRes.dissat

  of MsThresh:
    # thresh(k, X1, ..., Xn) - satisfy exactly k of n
    # Uses dynamic programming similar to multi
    var subResults: seq[SatisfactionResult]
    for sub in node.subs:
      subResults.add(satisfyImpl(sub, ctx, msCtx))

    # DP: sats[j] = best way to satisfy exactly j subexpressions
    var sats: seq[InputStack] = @[newInputStack()]

    for i in 0 ..< node.subs.len:
      let res = subResults[node.subs.len - 1 - i]  # Process in reverse
      var nextSats: seq[InputStack]
      nextSats.add(sats[0] + res.dissat)
      for j in 1 ..< sats.len:
        nextSats.add((sats[j] + res.dissat) | (sats[j-1] + res.sat))
      nextSats.add(sats[^1] + res.sat)
      sats = nextSats

    if node.threshold < sats.len:
      result.sat = sats[node.threshold]
    else:
      result.sat = InputStack(available: AvailNo)

    result.dissat = sats[0]  # All dissatisfied

  of MsMulti:
    # multi(k, key1, ..., keyn)
    # Satisfaction: dummy sig1 sig2 ... sigk
    # Dissatisfaction: dummy 0 0 ... 0 (k+1 zeros)

    # Collect available signatures
    var availableSigs: seq[tuple[idx: int, sig: seq[byte]]]
    for i, key in node.keys:
      if ctx.availableKeys.hasKey(key):
        availableSigs.add((i, ctx.availableKeys[key]))

    # Dissatisfaction: k+1 zeros (dummy + k zeros)
    var dissatStack = newInputStackZero()  # dummy
    for _ in 0 ..< node.k:
      dissatStack = dissatStack + newInputStackZero()
    result.dissat = dissatStack

    # Satisfaction requires at least k signatures
    if availableSigs.len >= node.k:
      # Sort by index and take first k
      availableSigs.sort(proc(a, b: tuple[idx: int, sig: seq[byte]]): int = cmp(a.idx, b.idx))

      var satStack = newInputStackZero()  # dummy (CHECKMULTISIG bug)
      for i in 0 ..< node.k:
        var sig = newInputStack(availableSigs[i].sig)
        sig.hasSig = true
        satStack = satStack + sig
      result.sat = satStack
    else:
      result.sat = InputStack(available: AvailNo)

  of MsMultiA:
    # multi_a(k, key1, ..., keyn) - tapscript
    # Satisfaction: sig_n sig_{n-1} ... sig_1 (signatures in reverse key order)
    # For non-signing keys, push empty signature

    # Collect available signatures (must be in key order, pushed in reverse)
    var sigsOrEmpty: seq[InputStack]
    var sigCount = 0

    for key in node.keys:
      if ctx.availableKeys.hasKey(key):
        var sig = newInputStack(ctx.availableKeys[key])
        sig.hasSig = true
        sigsOrEmpty.add(sig)
        inc sigCount
      else:
        sigsOrEmpty.add(newInputStackZero())  # Empty sig for non-signing

    # Reverse for proper witness order
    sigsOrEmpty.reverse()

    # Dissatisfaction: all empty
    var dissatStack = newInputStack()
    for _ in 0 ..< node.keys.len:
      dissatStack = dissatStack + newInputStackZero()
    result.dissat = dissatStack

    if sigCount >= node.k:
      var satStack = newInputStack()
      for s in sigsOrEmpty:
        satStack = satStack + s
      result.sat = satStack
    else:
      result.sat = InputStack(available: AvailNo)

proc satisfy*(node: MsNode, ctx: SigningContext, msCtx: MsContext = MsP2WSH): SatisfactionResult =
  satisfyImpl(node, ctx, msCtx)

proc getWitness*(node: MsNode, ctx: SigningContext, msCtx: MsContext = MsP2WSH): Option[seq[seq[byte]]] =
  ## Get the witness stack for satisfying this miniscript
  let res = satisfy(node, ctx, msCtx)
  if res.sat.available == AvailYes:
    return some(res.sat.stack)
  return none(seq[seq[byte]])

# =============================================================================
# Analysis
# =============================================================================

proc maxWitnessSize*(node: MsNode, ctx: MsContext = MsP2WSH): int =
  ## Compute maximum witness size for this miniscript
  let isTapscript = ctx == MsTapscript

  case node.kind
  of MsJust0, MsJust1:
    result = 0

  of MsPkK:
    # Max signature size
    result = if isTapscript: 65 else: 73  # Schnorr vs DER

  of MsPkH:
    # signature + pubkey
    result = (if isTapscript: 65 else: 73) + 34  # sig + push + 33 byte pubkey

  of MsOlder, MsAfter:
    result = 0  # No witness data, just script check

  of MsSha256, MsHash256, MsRipemd160, MsHash160:
    result = 33  # 32 byte preimage + push

  of MsWrapA, MsWrapS, MsWrapN:
    result = maxWitnessSize(node.sub, ctx)

  of MsWrapC, MsWrapV:
    result = maxWitnessSize(node.sub, ctx)

  of MsWrapD, MsWrapJ:
    result = maxWitnessSize(node.sub, ctx) + 1

  of MsAndV, MsAndB:
    result = maxWitnessSize(node.left, ctx) + maxWitnessSize(node.right, ctx)

  of MsOrB:
    let left = maxWitnessSize(node.left, ctx) + 1  # + dissat
    let right = maxWitnessSize(node.right, ctx) + 1
    result = max(left, right)

  of MsOrC, MsOrD:
    let left = maxWitnessSize(node.left, ctx)
    let right = maxWitnessSize(node.right, ctx) + 1  # + dissat for left
    result = max(left, right)

  of MsOrI:
    let left = maxWitnessSize(node.left, ctx) + 1  # + selector
    let right = maxWitnessSize(node.right, ctx) + 1
    result = max(left, right)

  of MsAndOr:
    let satXY = maxWitnessSize(node.x, ctx) + maxWitnessSize(node.y, ctx)
    let satZ = 1 + maxWitnessSize(node.z, ctx)  # + dissat for X
    result = max(satXY, satZ)

  of MsThresh:
    # Satisfy k of n, dissatisfy n-k
    var total = 0
    var sizes: seq[int]
    for sub in node.subs:
      sizes.add(maxWitnessSize(sub, ctx))
    sizes.sort()
    sizes.reverse()
    # Take k largest
    for i in 0 ..< node.threshold:
      total += sizes[i]
    # Add dissatisfaction for rest
    total += (node.subs.len - node.threshold)
    result = total

  of MsMulti:
    # k signatures + dummy
    let sigSize = 73  # DER max
    result = node.k * (sigSize + 1) + 1  # sigs + dummy

  of MsMultiA:
    # n signatures (or empty) total
    let sigSize = 65  # Schnorr
    result = node.keys.len * (sigSize + 1)

proc requiredKeys*(node: MsNode): seq[PublicKey] =
  ## Get all keys required for any satisfaction
  case node.kind
  of MsJust0, MsJust1, MsOlder, MsAfter,
     MsSha256, MsHash256, MsRipemd160, MsHash160:
    result = @[]

  of MsPkK, MsPkH:
    result = @[node.key]

  of MsWrapA, MsWrapS, MsWrapC, MsWrapD, MsWrapV, MsWrapJ, MsWrapN:
    result = requiredKeys(node.sub)

  of MsAndV, MsAndB:
    result = requiredKeys(node.left) & requiredKeys(node.right)

  of MsOrB, MsOrC, MsOrD, MsOrI:
    # Either branch may be used
    result = requiredKeys(node.left)
    for k in requiredKeys(node.right):
      if k notin result:
        result.add(k)

  of MsAndOr:
    result = requiredKeys(node.x)
    for k in requiredKeys(node.y):
      if k notin result:
        result.add(k)
    for k in requiredKeys(node.z):
      if k notin result:
        result.add(k)

  of MsThresh:
    for sub in node.subs:
      for k in requiredKeys(sub):
        if k notin result:
          result.add(k)

  of MsMulti, MsMultiA:
    result = node.keys

proc hasTimelockConflict*(node: MsNode): bool =
  ## Check if the miniscript has conflicting timelocks
  ## (mixing time-based and height-based locks that can't both be satisfied)

  var hasTimeOlder = false
  var hasHeightOlder = false
  var hasTimeAfter = false
  var hasHeightAfter = false

  proc checkNode(n: MsNode) =
    case n.kind
    of MsOlder:
      if (n.lockValue and SequenceLocktimeTypeFlag) != 0:
        hasTimeOlder = true
      else:
        hasHeightOlder = true
    of MsAfter:
      if n.lockValue >= LocktimeThreshold:
        hasTimeAfter = true
      else:
        hasHeightAfter = true
    of MsWrapA, MsWrapS, MsWrapC, MsWrapD, MsWrapV, MsWrapJ, MsWrapN:
      checkNode(n.sub)
    of MsAndV, MsAndB:
      checkNode(n.left)
      checkNode(n.right)
    of MsOrB, MsOrC, MsOrD, MsOrI:
      checkNode(n.left)
      checkNode(n.right)
    of MsAndOr:
      checkNode(n.x)
      checkNode(n.y)
      checkNode(n.z)
    of MsThresh:
      for sub in n.subs:
        checkNode(sub)
    else:
      discard

  checkNode(node)

  # Conflict if mixing time and height for same lock type
  result = (hasTimeOlder and hasHeightOlder) or (hasTimeAfter and hasHeightAfter)

# =============================================================================
# Parsing
# =============================================================================

proc parseMiniscript*(s: string, ctx: MsContext = MsP2WSH): MsNode

proc skipWhitespace(s: string, pos: var int) =
  while pos < s.len and s[pos] in {' ', '\t', '\n', '\r'}:
    inc pos

proc expectChar(s: string, pos: var int, c: char) =
  if pos >= s.len or s[pos] != c:
    raise newException(MiniscriptError, "expected '" & c & "' at position " & $pos)
  inc pos

proc parseUntil(s: string, pos: var int, delims: set[char]): string =
  let start = pos
  while pos < s.len and s[pos] notin delims:
    inc pos
  s[start ..< pos]

proc parseFunctionName(s: string, pos: var int): string =
  let start = pos
  while pos < s.len and s[pos] in {'a'..'z', 'A'..'Z', '_', '0'..'9'}:
    inc pos
  s[start ..< pos]

proc parseHex(s: string): seq[byte] =
  if s.len mod 2 != 0:
    raise newException(MiniscriptError, "odd hex string length")
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[i*2 ..< i*2+2]))

proc parsePublicKey(s: string): PublicKey =
  let bytes = parseHex(s)
  if bytes.len == 33:
    copyMem(addr result[0], addr bytes[0], 33)
  elif bytes.len == 32:
    # X-only, convert to compressed (assume even parity)
    result[0] = 0x02
    copyMem(addr result[1], addr bytes[0], 32)
  else:
    raise newException(MiniscriptError, "invalid public key length: " & $bytes.len)

proc parseMiniscriptImpl(s: string, pos: var int, ctx: MsContext): MsNode =
  skipWhitespace(s, pos)

  # Check for wrappers (single character followed by :)
  if pos + 1 < s.len and s[pos + 1] == ':':
    let wrapper = s[pos]
    pos += 2  # Skip wrapper and colon

    let sub = parseMiniscriptImpl(s, pos, ctx)

    case wrapper
    of 'a':
      return MsNode(kind: MsWrapA, sub: sub)
    of 's':
      return MsNode(kind: MsWrapS, sub: sub)
    of 'c':
      return MsNode(kind: MsWrapC, sub: sub)
    of 'd':
      return MsNode(kind: MsWrapD, sub: sub)
    of 'v':
      return MsNode(kind: MsWrapV, sub: sub)
    of 'j':
      return MsNode(kind: MsWrapJ, sub: sub)
    of 'n':
      return MsNode(kind: MsWrapN, sub: sub)
    of 'l':
      # l:X = or_i(0,X)
      return MsNode(kind: MsOrI, left: MsNode(kind: MsJust0), right: sub)
    of 'u':
      # u:X = or_i(X,0)
      return MsNode(kind: MsOrI, left: sub, right: MsNode(kind: MsJust0))
    of 't':
      # t:X = and_v(X,1)
      return MsNode(kind: MsAndV, left: sub, right: MsNode(kind: MsJust1))
    else:
      raise newException(MiniscriptError, "unknown wrapper: " & wrapper)

  let funcName = parseFunctionName(s, pos)
  skipWhitespace(s, pos)
  expectChar(s, pos, '(')

  case funcName.toLowerAscii()
  of "0":
    skipWhitespace(s, pos)
    expectChar(s, pos, ')')
    result = MsNode(kind: MsJust0)

  of "1":
    skipWhitespace(s, pos)
    expectChar(s, pos, ')')
    result = MsNode(kind: MsJust1)

  of "pk", "pk_k":
    skipWhitespace(s, pos)
    let keyStr = parseUntil(s, pos, {')', ','})
    skipWhitespace(s, pos)
    expectChar(s, pos, ')')
    result = MsNode(kind: MsPkK, key: parsePublicKey(keyStr.strip()))

  of "pkh", "pk_h":
    skipWhitespace(s, pos)
    let keyStr = parseUntil(s, pos, {')', ','})
    skipWhitespace(s, pos)
    expectChar(s, pos, ')')
    result = MsNode(kind: MsPkH, key: parsePublicKey(keyStr.strip()))

  of "older":
    skipWhitespace(s, pos)
    let numStr = parseUntil(s, pos, {')'})
    skipWhitespace(s, pos)
    expectChar(s, pos, ')')
    result = MsNode(kind: MsOlder, lockValue: parseUInt(numStr.strip()).uint32)

  of "after":
    skipWhitespace(s, pos)
    let numStr = parseUntil(s, pos, {')'})
    skipWhitespace(s, pos)
    expectChar(s, pos, ')')
    result = MsNode(kind: MsAfter, lockValue: parseUInt(numStr.strip()).uint32)

  of "sha256":
    skipWhitespace(s, pos)
    let hashStr = parseUntil(s, pos, {')'})
    skipWhitespace(s, pos)
    expectChar(s, pos, ')')
    let bytes = parseHex(hashStr.strip())
    if bytes.len != 32:
      raise newException(MiniscriptError, "sha256 requires 32-byte hash")
    var hash: array[32, byte]
    copyMem(addr hash[0], addr bytes[0], 32)
    result = MsNode(kind: MsSha256, hash32: hash)

  of "hash256":
    skipWhitespace(s, pos)
    let hashStr = parseUntil(s, pos, {')'})
    skipWhitespace(s, pos)
    expectChar(s, pos, ')')
    let bytes = parseHex(hashStr.strip())
    if bytes.len != 32:
      raise newException(MiniscriptError, "hash256 requires 32-byte hash")
    var hash: array[32, byte]
    copyMem(addr hash[0], addr bytes[0], 32)
    result = MsNode(kind: MsHash256, hash32: hash)

  of "ripemd160":
    skipWhitespace(s, pos)
    let hashStr = parseUntil(s, pos, {')'})
    skipWhitespace(s, pos)
    expectChar(s, pos, ')')
    let bytes = parseHex(hashStr.strip())
    if bytes.len != 20:
      raise newException(MiniscriptError, "ripemd160 requires 20-byte hash")
    var hash: array[20, byte]
    copyMem(addr hash[0], addr bytes[0], 20)
    result = MsNode(kind: MsRipemd160, hash20: hash)

  of "hash160":
    skipWhitespace(s, pos)
    let hashStr = parseUntil(s, pos, {')'})
    skipWhitespace(s, pos)
    expectChar(s, pos, ')')
    let bytes = parseHex(hashStr.strip())
    if bytes.len != 20:
      raise newException(MiniscriptError, "hash160 requires 20-byte hash")
    var hash: array[20, byte]
    copyMem(addr hash[0], addr bytes[0], 20)
    result = MsNode(kind: MsHash160, hash20: hash)

  of "and_v":
    let x = parseMiniscriptImpl(s, pos, ctx)
    skipWhitespace(s, pos)
    expectChar(s, pos, ',')
    let y = parseMiniscriptImpl(s, pos, ctx)
    skipWhitespace(s, pos)
    expectChar(s, pos, ')')
    result = MsNode(kind: MsAndV, left: x, right: y)

  of "and_b":
    let x = parseMiniscriptImpl(s, pos, ctx)
    skipWhitespace(s, pos)
    expectChar(s, pos, ',')
    let y = parseMiniscriptImpl(s, pos, ctx)
    skipWhitespace(s, pos)
    expectChar(s, pos, ')')
    result = MsNode(kind: MsAndB, left: x, right: y)

  of "or_b":
    let x = parseMiniscriptImpl(s, pos, ctx)
    skipWhitespace(s, pos)
    expectChar(s, pos, ',')
    let y = parseMiniscriptImpl(s, pos, ctx)
    skipWhitespace(s, pos)
    expectChar(s, pos, ')')
    result = MsNode(kind: MsOrB, left: x, right: y)

  of "or_c":
    let x = parseMiniscriptImpl(s, pos, ctx)
    skipWhitespace(s, pos)
    expectChar(s, pos, ',')
    let y = parseMiniscriptImpl(s, pos, ctx)
    skipWhitespace(s, pos)
    expectChar(s, pos, ')')
    result = MsNode(kind: MsOrC, left: x, right: y)

  of "or_d":
    let x = parseMiniscriptImpl(s, pos, ctx)
    skipWhitespace(s, pos)
    expectChar(s, pos, ',')
    let y = parseMiniscriptImpl(s, pos, ctx)
    skipWhitespace(s, pos)
    expectChar(s, pos, ')')
    result = MsNode(kind: MsOrD, left: x, right: y)

  of "or_i":
    let x = parseMiniscriptImpl(s, pos, ctx)
    skipWhitespace(s, pos)
    expectChar(s, pos, ',')
    let y = parseMiniscriptImpl(s, pos, ctx)
    skipWhitespace(s, pos)
    expectChar(s, pos, ')')
    result = MsNode(kind: MsOrI, left: x, right: y)

  of "andor":
    let x = parseMiniscriptImpl(s, pos, ctx)
    skipWhitespace(s, pos)
    expectChar(s, pos, ',')
    let y = parseMiniscriptImpl(s, pos, ctx)
    skipWhitespace(s, pos)
    expectChar(s, pos, ',')
    let z = parseMiniscriptImpl(s, pos, ctx)
    skipWhitespace(s, pos)
    expectChar(s, pos, ')')
    result = MsNode(kind: MsAndOr, x: x, y: y, z: z)

  of "thresh":
    skipWhitespace(s, pos)
    let kStr = parseUntil(s, pos, {','})
    let k = parseInt(kStr.strip())

    var subs: seq[MsNode]
    while pos < s.len and s[pos] == ',':
      inc pos
      subs.add(parseMiniscriptImpl(s, pos, ctx))
      skipWhitespace(s, pos)

    expectChar(s, pos, ')')

    if k < 1 or k > subs.len:
      raise newException(MiniscriptError, "invalid threshold")

    result = MsNode(kind: MsThresh, threshold: k, subs: subs)

  of "multi":
    if ctx == MsTapscript:
      raise newException(MiniscriptError, "multi not allowed in tapscript, use multi_a")

    skipWhitespace(s, pos)
    let kStr = parseUntil(s, pos, {','})
    let k = parseInt(kStr.strip())

    var keys: seq[PublicKey]
    while pos < s.len and s[pos] == ',':
      inc pos
      skipWhitespace(s, pos)
      let keyStr = parseUntil(s, pos, {',', ')'})
      keys.add(parsePublicKey(keyStr.strip()))
      skipWhitespace(s, pos)

    expectChar(s, pos, ')')

    if k < 1 or k > keys.len or keys.len > MaxMultiKeys:
      raise newException(MiniscriptError, "invalid multi parameters")

    result = MsNode(kind: MsMulti, k: k, keys: keys)

  of "multi_a":
    if ctx != MsTapscript:
      raise newException(MiniscriptError, "multi_a only allowed in tapscript")

    skipWhitespace(s, pos)
    let kStr = parseUntil(s, pos, {','})
    let k = parseInt(kStr.strip())

    var keys: seq[PublicKey]
    while pos < s.len and s[pos] == ',':
      inc pos
      skipWhitespace(s, pos)
      let keyStr = parseUntil(s, pos, {',', ')'})
      keys.add(parsePublicKey(keyStr.strip()))
      skipWhitespace(s, pos)

    expectChar(s, pos, ')')

    if k < 1 or k > keys.len or keys.len > MaxMultiAKeys:
      raise newException(MiniscriptError, "invalid multi_a parameters")

    result = MsNode(kind: MsMultiA, k: k, keys: keys)

  else:
    raise newException(MiniscriptError, "unknown miniscript function: " & funcName)

proc parseMiniscript*(s: string, ctx: MsContext = MsP2WSH): MsNode =
  ## Parse a miniscript expression string
  var pos = 0
  result = parseMiniscriptImpl(s, pos, ctx)

  skipWhitespace(s, pos)
  if pos < s.len:
    raise newException(MiniscriptError, "unexpected characters after miniscript")

  # Compute and cache type
  result.msType = computeType(result, ctx)
  result.scriptLen = compile(result, ctx).len

# =============================================================================
# String Conversion
# =============================================================================

proc toString*(node: MsNode): string =
  ## Convert miniscript node to string representation
  case node.kind
  of MsJust0:
    result = "0"
  of MsJust1:
    result = "1"
  of MsPkK:
    result = "pk_k(" & bytesToHex(@(node.key)) & ")"
  of MsPkH:
    result = "pk_h(" & bytesToHex(@(node.key)) & ")"
  of MsOlder:
    result = "older(" & $node.lockValue & ")"
  of MsAfter:
    result = "after(" & $node.lockValue & ")"
  of MsSha256:
    result = "sha256(" & bytesToHex(@(node.hash32)) & ")"
  of MsHash256:
    result = "hash256(" & bytesToHex(@(node.hash32)) & ")"
  of MsRipemd160:
    result = "ripemd160(" & bytesToHex(@(node.hash20)) & ")"
  of MsHash160:
    result = "hash160(" & bytesToHex(@(node.hash20)) & ")"
  of MsWrapA:
    result = "a:" & toString(node.sub)
  of MsWrapS:
    result = "s:" & toString(node.sub)
  of MsWrapC:
    result = "c:" & toString(node.sub)
  of MsWrapD:
    result = "d:" & toString(node.sub)
  of MsWrapV:
    result = "v:" & toString(node.sub)
  of MsWrapJ:
    result = "j:" & toString(node.sub)
  of MsWrapN:
    result = "n:" & toString(node.sub)
  of MsAndV:
    result = "and_v(" & toString(node.left) & "," & toString(node.right) & ")"
  of MsAndB:
    result = "and_b(" & toString(node.left) & "," & toString(node.right) & ")"
  of MsOrB:
    result = "or_b(" & toString(node.left) & "," & toString(node.right) & ")"
  of MsOrC:
    result = "or_c(" & toString(node.left) & "," & toString(node.right) & ")"
  of MsOrD:
    result = "or_d(" & toString(node.left) & "," & toString(node.right) & ")"
  of MsOrI:
    result = "or_i(" & toString(node.left) & "," & toString(node.right) & ")"
  of MsAndOr:
    result = "andor(" & toString(node.x) & "," & toString(node.y) & "," & toString(node.z) & ")"
  of MsThresh:
    result = "thresh(" & $node.threshold
    for sub in node.subs:
      result.add("," & toString(sub))
    result.add(")")
  of MsMulti:
    result = "multi(" & $node.k
    for key in node.keys:
      result.add("," & bytesToHex(@key))
    result.add(")")
  of MsMultiA:
    result = "multi_a(" & $node.k
    for key in node.keys:
      result.add("," & bytesToHex(@key))
    result.add(")")

