## Unit tests for the OFFLINE PSBT-secondary RPCs converttopsbt + joinpsbts
## (nimrod parity with Bitcoin Core v31.99 rpc/rawtransaction.cpp).
##
## These exercise the thin offline wrappers directly via RpcServer.handleMethod
## with a BARE RpcServer (the handlers never dereference `rpc`), so NO node,
## NO chainstate, NO regtest is required.
##
## Run ONLY this file:
##   nim c --nimcache:/tmp/psbtnim -r tests/test_psbt_convert_join.nim
## then delete the compiled binary it leaves in tests/.

import std/[unittest, options, base64, tables, sets, sequtils, algorithm, strutils]
import ../src/rpc/server
import ../src/wallet/psbt
import ../src/primitives/[types, serialize]
import std/json

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

proc mkTxId(seedByte: byte): TxId =
  ## Deterministic 32-byte txid filled with `seedByte`.
  var a: array[32, byte]
  for i in 0 ..< 32:
    a[i] = seedByte
  TxId(a)

proc mkInput(seedByte: byte, vout: uint32,
             scriptSig: seq[byte] = @[]): TxIn =
  TxIn(
    prevOut: OutPoint(txid: mkTxId(seedByte), vout: vout),
    scriptSig: scriptSig,
    sequence: 0xffffffff'u32)

proc mkOutput(value: int64, spk: seq[byte]): TxOut =
  TxOut(value: Satoshi(value), scriptPubKey: spk)

proc mkPsbtBase64(inputs: seq[TxIn], outputs: seq[TxOut],
                  version: int32 = 2, lockTime: uint32 = 0): string =
  ## Build a blank PSBT (empty maps) and base64-encode it. scriptSigs MUST be
  ## empty (createPsbt enforces this), mirroring a real unsigned PSBT.
  let tx = Transaction(
    version: version,
    inputs: inputs,
    outputs: outputs,
    witnesses: @[],
    lockTime: lockTime)
  createPsbt(tx).toBase64()

proc bare(): RpcServer =
  ## A zero-initialized RpcServer; the offline PSBT handlers never read any
  ## of its fields, so this is sufficient to drive handleMethod.
  RpcServer()

proc toHexStr(data: openArray[byte]): string =
  result = ""
  const hexd = "0123456789abcdef"
  for b in data:
    result.add(hexd[int(b shr 4)])
    result.add(hexd[int(b and 0x0f)])

# Decode a base64 PSBT result back into a Psbt and return its outpoint set
# + output (value, spk) multiset for set-based comparison.
proc inputSet(p: Psbt): HashSet[(TxId, uint32)] =
  result = initHashSet[(TxId, uint32)]()
  for inp in p.tx.get().inputs:
    result.incl((inp.prevOut.txid, inp.prevOut.vout))

proc outputMultiset(p: Psbt): seq[(int64, string)] =
  ## Outputs may legitimately repeat; return a SORTED list so equality is
  ## order-independent (joinpsbts shuffles).
  result = @[]
  for o in p.tx.get().outputs:
    result.add((int64(o.value), toHexStr(o.scriptPubKey)))
  result.sort()

# ===========================================================================
# converttopsbt
# ===========================================================================

suite "converttopsbt (offline)":

  test "input with scriptSig throws -22 unless permitsigdata":
    # A legacy tx with a non-empty scriptSig on its sole input.
    let sig = @[0x47'u8, 0x30, 0x44]  # arbitrary non-empty scriptSig bytes
    let tx = Transaction(
      version: 2,
      inputs: @[mkInput(0x11, 0, sig)],
      outputs: @[mkOutput(50_000, @[0x6a'u8])],  # OP_RETURN-ish spk
      witnesses: @[],
      lockTime: 0)
    let hexStr = toHexStr(tx.serialize(includeWitness = false))

    # permitsigdata omitted (defaults false) → must throw -22 with the exact
    # Core message.
    var threw = false
    try:
      discard bare().handleMethod("converttopsbt", %*[hexStr])
    except RpcError as e:
      threw = true
      check e.code == -22
      check e.msg == "Inputs must not have scriptSigs and scriptWitnesses"
    check threw

    # permitsigdata = false explicitly → still throws.
    threw = false
    try:
      discard bare().handleMethod("converttopsbt", %*[hexStr, false])
    except RpcError as e:
      threw = true
      check e.code == -22
    check threw

  test "permitsigdata=true clears sig data and round-trips a blank PSBT":
    let sig = @[0x47'u8, 0x30, 0x44]
    let tx = Transaction(
      version: 2,
      inputs: @[mkInput(0x22, 3, sig), mkInput(0x33, 1, @[0x51'u8])],
      outputs: @[mkOutput(12_345, @[0x00'u8, 0x14'u8] & repeat(0xaa'u8, 20)),
                 mkOutput(99, @[0x6a'u8, 0x01'u8, 0x07'u8])],
      witnesses: @[],
      lockTime: 7)
    let hexStr = toHexStr(tx.serialize(includeWitness = false))

    let res = bare().handleMethod("converttopsbt", %*[hexStr, true])
    check res.kind == JString

    let p = fromBase64(res.getStr())
    # Blank maps: one empty input map per vin, one empty output map per vout.
    check p.inputs.len == 2
    check p.outputs.len == 2
    for i in p.inputs:
      check i.isNull()
    for o in p.outputs:
      check o.isNull()
    check p.xpubs.len == 0
    check p.unknown.len == 0

    # The embedded unsigned tx must equal the CLEARED tx: same prevouts,
    # outputs, version, locktime — but scriptSigs wiped.
    let ptx = p.tx.get()
    check ptx.version == 2
    check ptx.lockTime == 7
    check ptx.inputs.len == 2
    for inp in ptx.inputs:
      check inp.scriptSig.len == 0            # cleared
    # prevouts preserved
    check ptx.inputs[0].prevOut.txid == mkTxId(0x22)
    check ptx.inputs[0].prevOut.vout == 3'u32
    check ptx.inputs[1].prevOut.txid == mkTxId(0x33)
    check ptx.inputs[1].prevOut.vout == 1'u32
    # outputs preserved (value + spk)
    check int64(ptx.outputs[0].value) == 12_345
    check int64(ptx.outputs[1].value) == 99

  test "clean tx (no sig data) converts without permitsigdata":
    let tx = Transaction(
      version: 2,
      inputs: @[mkInput(0x44, 0)],
      outputs: @[mkOutput(1000, @[0x6a'u8])],
      witnesses: @[],
      lockTime: 0)
    let hexStr = toHexStr(tx.serialize(includeWitness = false))
    let res = bare().handleMethod("converttopsbt", %*[hexStr])
    let p = fromBase64(res.getStr())
    check p.inputs.len == 1
    check p.outputs.len == 1
    check p.inputs[0].isNull()
    check p.outputs[0].isNull()

  # ---------------------------------------------------------------------------
  # Empty-vin tx: the leading 0x00 vin-count is mis-read as a segwit marker by
  # the witness-aware decoder, which then parses a TRUNCATED 0-input/0-output tx
  # without consuming all bytes. Core's DecodeTx requires full byte consumption
  # (ssData.empty()) before accepting a candidate decode, so it falls back to the
  # legacy decoder and preserves the real output. This must NOT silently drop the
  # OP_RETURN output `6a0400010203`.
  #
  # NOTE: we assert directly on the base64 (the Core v31.99 oracle) rather than
  # round-tripping through fromBase64, because the PSBT parser deserializes its
  # embedded unsigned tx with the SAME witness-first deserializer (psbt.nim:934)
  # and would re-trigger the empty-vin mis-parse — that is a separate code path
  # outside this fix's scope. We additionally re-parse the PSBT's embedded
  # unsigned-tx bytes with an explicit LEGACY reader to prove nin=0/nout=1.
  # ---------------------------------------------------------------------------
  const emptyVinHex =
    "0200000000010000000000000000066a040001020300000000"
  # base64 of the blank PSBT Core produces for emptyVinHex (nin=0, nout=1).
  const emptyVinPsbtB64 =
    "cHNidP8BABkCAAAAAAEAAAAAAAAAAAZqBAABAgMAAAAAAAA="

  # Extract the PSBT global PSBT_GLOBAL_UNSIGNED_TX (keytype 0x00) value bytes,
  # then parse them with an EXPLICIT legacy reader (no segwit-marker heuristic),
  # returning (version, ninputs, noutputs, lockTime, out0-scriptPubKey-hex).
  proc embeddedTxLegacy(psbtB64: string):
      tuple[version: int32, nin: int, nout: int, lockTime: uint32, spk0: string] =
    let raw = cast[seq[byte]](decode(psbtB64))
    # magic "psbt\xff" (5 bytes) then the global key-value map.
    var r = BinaryReader(data: raw, pos: 5)
    var txBytes: seq[byte] = @[]
    while true:
      let keyLen = int(r.readCompactSize())
      if keyLen == 0:
        break                                 # global-map separator
      let key = r.readBytes(keyLen)
      let value = r.readVarBytes()
      if key.len == 1 and key[0] == 0x00'u8:   # PSBT_GLOBAL_UNSIGNED_TX
        txBytes = value
    doAssert txBytes.len > 0, "no unsigned tx in PSBT"
    # Legacy parse (mirrors decodeRawTxLegacyForced): no segwit-marker heuristic.
    var tr = BinaryReader(data: txBytes, pos: 0)
    let ver = tr.readInt32LE()
    let nin = int(tr.readCompactSize())
    for _ in 0 ..< nin: discard tr.readTxIn()
    let nout = int(tr.readCompactSize())
    var outs: seq[TxOut] = @[]
    for _ in 0 ..< nout: outs.add(tr.readTxOut())
    let lt = tr.readUint32LE()
    let spk0 = if outs.len > 0: toHexStr(outs[0].scriptPubKey) else: ""
    (ver, nin, nout, lt, spk0)

  test "empty-vin tx (heuristic, no iswitness) keeps the output via legacy fallback":
    let res = bare().handleMethod("converttopsbt", %*[emptyVinHex])
    check res.kind == JString
    # Byte-identical to Bitcoin Core v31.99's converttopsbt output.
    check res.getStr() == emptyVinPsbtB64

    # The witness-first parse would have produced 0 inputs AND 0 outputs; the
    # legacy fallback must recover the single real OP_RETURN output.
    let (ver, nin, nout, lt, spk0) = embeddedTxLegacy(res.getStr())
    check ver == 2'i32
    check nin == 0
    check nout == 1
    check lt == 0'u32
    check spk0 == "6a0400010203"

  test "empty-vin tx with iswitness=true throws -22 (witness parse cannot fully consume)":
    var threw = false
    try:
      discard bare().handleMethod("converttopsbt", %*[emptyVinHex, false, true])
    except RpcError as e:
      threw = true
      check e.code == -22
      check e.msg == "TX decode failed"
    check threw

  test "empty-vin tx with iswitness=false yields the same nin=0/nout=1 PSBT":
    let res = bare().handleMethod("converttopsbt", %*[emptyVinHex, false, false])
    check res.kind == JString
    check res.getStr() == emptyVinPsbtB64

    let (ver, nin, nout, lt, spk0) = embeddedTxLegacy(res.getStr())
    check ver == 2'i32
    check nin == 0
    check nout == 1
    check lt == 0'u32
    check spk0 == "6a0400010203"

# ===========================================================================
# joinpsbts
# ===========================================================================

suite "joinpsbts (offline)":

  test "fewer than two PSBTs throws -8":
    let single = mkPsbtBase64(@[mkInput(0x01, 0)], @[mkOutput(100, @[0x6a'u8])])
    var threw = false
    try:
      discard bare().handleMethod("joinpsbts", %*[[single]])
    except RpcError as e:
      threw = true
      check e.code == -8
      check e.msg == "At least two PSBTs are required to join PSBTs."
    check threw

    # Empty array also < 2 → -8.
    threw = false
    try:
      discard bare().handleMethod("joinpsbts", %*[newJArray()])
    except RpcError as e:
      threw = true
      check e.code == -8
    check threw

  test "duplicate input across PSBTs throws -8":
    # Both PSBTs spend the SAME prevout (txid 0x05, vout 2).
    let a = mkPsbtBase64(@[mkInput(0x05, 2)], @[mkOutput(100, @[0x6a'u8])])
    let b = mkPsbtBase64(@[mkInput(0x05, 2)], @[mkOutput(200, @[0x6a'u8])])
    var threw = false
    try:
      discard bare().handleMethod("joinpsbts", %*[[a, b]])
    except RpcError as e:
      threw = true
      check e.code == -8
      check e.msg.startsWith("Input ")
      check e.msg.endsWith(" exists in multiple PSBTs")
      check e.msg.contains(":2")
    check threw

  test "bad base64 PSBT throws -22":
    let good = mkPsbtBase64(@[mkInput(0x06, 0)], @[mkOutput(100, @[0x6a'u8])])
    var threw = false
    try:
      discard bare().handleMethod("joinpsbts", %*[[good, "not-a-psbt!!!"]])
    except RpcError as e:
      threw = true
      check e.code == -22
      check e.msg.startsWith("TX decode failed")
    check threw

  test "join two distinct PSBTs yields the UNION (as sets) of inputs+outputs":
    # PSBT A: version 1, locktime 500; one input, one output.
    let a = mkPsbtBase64(
      @[mkInput(0xa1, 0)],
      @[mkOutput(1000, @[0x6a'u8, 0xa1'u8])],
      version = 1, lockTime = 500)
    # PSBT B: version 3, locktime 100; two inputs, one output.
    let b = mkPsbtBase64(
      @[mkInput(0xb1, 1), mkInput(0xb2, 7)],
      @[mkOutput(2000, @[0x6a'u8, 0xb1'u8])],
      version = 3, lockTime = 100)

    let res = bare().handleMethod("joinpsbts", %*[[a, b]])
    check res.kind == JString
    let joined = fromBase64(res.getStr())
    let jtx = joined.tx.get()

    # max version (3) + min locktime (100).
    check jtx.version == 3'i32
    check jtx.lockTime == 100'u32

    # Inputs: union of {a1:0, b1:1, b2:7}, compared as a SET (shuffled order).
    let gotIns = joined.inputSet()
    var wantIns = initHashSet[(TxId, uint32)]()
    wantIns.incl((mkTxId(0xa1), 0'u32))
    wantIns.incl((mkTxId(0xb1), 1'u32))
    wantIns.incl((mkTxId(0xb2), 7'u32))
    check gotIns == wantIns
    check jtx.inputs.len == 3
    # one empty PsbtInput map per input
    check joined.inputs.len == 3

    # Outputs: union (no dedup) of both outputs, compared as a sorted multiset.
    let gotOuts = joined.outputMultiset()
    var wantOuts = @[(1000'i64, toHexStr(@[0x6a'u8, 0xa1'u8])),
                     (2000'i64, toHexStr(@[0x6a'u8, 0xb1'u8]))]
    wantOuts.sort()
    check gotOuts == wantOuts
    check jtx.outputs.len == 2
    check joined.outputs.len == 2

  test "join preserves all distinct outputs even with equal scripts":
    # Two PSBTs each with an identical-looking output: joinpsbts does NOT dedup
    # outputs, so both must survive.
    let spk = @[0x76'u8, 0xa9'u8, 0x14'u8] & repeat(0xcc'u8, 20) & @[0x88'u8, 0xac'u8]
    let a = mkPsbtBase64(@[mkInput(0xc1, 0)], @[mkOutput(500, spk)])
    let b = mkPsbtBase64(@[mkInput(0xc2, 0)], @[mkOutput(500, spk)])
    let res = bare().handleMethod("joinpsbts", %*[[a, b]])
    let joined = fromBase64(res.getStr())
    check joined.tx.get().outputs.len == 2  # both kept, no dedup
    check joined.tx.get().inputs.len == 2
