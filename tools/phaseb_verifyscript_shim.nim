## Phase B `verifyscript` shim for nimrod.
##
## Drives nimrod's real consensus script interpreter
## (src/script/interpreter.nim::verifyScriptWithError) against the Phase B
## bounded reject-bar harness (tools/phaseb-vectors).
##
## It reconstructs the SAME crediting + spending transaction pair Core builds
## for its VerifyScript vectors
## (bitcoin-core/src/test/util/transaction_utils.cpp:
##  BuildCreditingTransaction / BuildSpendingTransaction) so that any
## signature-dependent rows compute an identical sighash, REUSING nimrod's own
## tx serialization + txid (primitives/serialize.nim) so the sighash matches
## byte-for-byte. Then it runs verifyScriptWithError with a flag set built by
## mapping all 22 Core flag tokens, and reports the accept/reject decision.
##
## Protocol (line-delimited JSON on stdin/stdout):
##   request:  {"op":"verifyscript",
##              "scriptSig_hex":"...","scriptPubKey_hex":"...",
##              "witness":["hex",...],"amount_sats":0,
##              "flags":["P2SH","WITNESS",...]}
##   response: {"result":true}                  (accept)
##             {"result":false,"reason":"..."}  (reject)
##             {"error":"..."}                  (could not evaluate)
##
## Second op `verifytx` (for tx_valid.json / tx_invalid.json): unlike
## `verifyscript` (which rebuilds Core's synthetic credit/spend pair),
## these vectors give a REAL serialized multi-input tx, so the sighash
## must be computed over THAT tx. Mirrors
## bitcoin-core/src/test/transaction_tests.cpp::CheckTxScripts: deserialize
## tx_hex with nimrod's OWN deserializer (parses the segwit marker/flag +
## per-input witnesses), build the prevout->(scriptPubKey, amount) map,
## then run verifyScriptWithError per input with the checker bound to THE
## REAL TX (input index + amount + all-prevouts) so the legacy/BIP-143/
## BIP-341 sighash commits to the actual surrounding transaction. The tx is
## valid iff ALL inputs pass; reject on the FIRST failing input (Core's loop
## is `i < vin.size() && tx_valid`).
##
##   request:  {"op":"verifytx",
##              "tx_hex":"...",
##              "prevouts":[{"txid":"<display-hex>","vout":N,
##                           "scriptPubKey_hex":"...","amount_sats":0},...],
##              "flags":["P2SH","WITNESS",...]}
##   response: {"valid":true}                   (all inputs verify)
##             {"valid":false,"reason":"..."}   (>=1 input failed)
##             {"error":"..."}                  (could not evaluate -> skip)
##
## Third op `checktx` (CheckTransaction-level, context-free structural
## validation): mirrors bitcoin-core/src/consensus/tx_check.cpp::
## CheckTransaction. These are the checks `verifytx` (per-input VerifyScript
## only) cannot catch — empty vin/vout, output value range and running
## total, duplicate inputs, oversize, coinbase scriptSig length, and a null
## prevout in a non-coinbase. We deserialize tx_hex and call nimrod's OWN
## `checkTransaction` (src/consensus/validation.nim:1620) so the harness
## exercises nimrod's consensus code, not a reimplementation in the shim.
## No UTXO/chain state is needed (params is passed but only the context-free
## gates G1..G9 run; mainnetParams() is a placeholder the proc never reads).
##
##   request:  {"op":"checktx","tx_hex":"..."}
##   response: {"valid":true}                   (structurally valid)
##             {"valid":false,"reason":"..."}   (CheckTransaction rejected)
##             {"error":"..."}                  (could not deserialize)
##
## Lives inside the nimrod submodule (not the meta-repo) so the local
## `nim.cfg` (-d:useSystemSecp256k1, library linkage) and the nimble dep
## paths in config.nims apply when compiling.

import std/[json, strutils, tables, options]
import ../src/primitives/types
import ../src/primitives/serialize
import ../src/script/interpreter
import ../src/consensus/validation
import ../src/consensus/params
import ../src/storage/chainstate
import ../src/consensus/pow

proc hexDecode(s: string): seq[byte] =
  if s.len mod 2 != 0:
    raise newException(ValueError, "odd hex length: " & $s.len)
  result = newSeqOfCap[byte](s.len div 2)
  var i = 0
  while i + 1 < s.len:
    result.add(byte(parseHexInt(s[i .. i+1])))
    i += 2

## Map Core flag tokens (interpreter.cpp:2168 ScriptFlagNamesToEnum) to
## nimrod's `ScriptFlags` enum set. Unknown token -> raise (shim emits
## {"error":...} so the driver skips rather than miscounts).
proc buildFlags(tokens: JsonNode): set[ScriptFlags] =
  result = {}
  for t in tokens:
    let name = t.getStr()
    case name
    of "P2SH": result.incl(sfP2SH)
    of "STRICTENC": result.incl(sfStrictEnc)
    of "DERSIG": result.incl(sfDERSig)
    of "LOW_S": result.incl(sfLowS)
    of "SIGPUSHONLY": result.incl(sfSigPushOnly)
    of "MINIMALDATA": result.incl(sfMinimalData)
    of "NULLDUMMY": result.incl(sfNullDummy)
    of "DISCOURAGE_UPGRADABLE_NOPS": result.incl(sfDiscourageUpgradableNops)
    of "CLEANSTACK": result.incl(sfCleanStack)
    of "MINIMALIF": result.incl(sfMinimalIf)
    of "NULLFAIL": result.incl(sfNullFail)
    of "CHECKLOCKTIMEVERIFY": result.incl(sfCheckLockTimeVerify)
    of "CHECKSEQUENCEVERIFY": result.incl(sfCheckSequenceVerify)
    of "WITNESS": result.incl(sfWitness)
    of "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM":
      result.incl(sfDiscourageUpgradableWitnessProgram)
    of "WITNESS_PUBKEYTYPE": result.incl(sfWitnessPubkeyType)
    of "CONST_SCRIPTCODE":
      # Maps to nimrod's sfConstScriptCode (SCRIPT_VERIFY_CONST_SCRIPTCODE).
      # The enforcement (FindAndDelete found>0 => SCRIPT_ERR_SIG_FINDANDDELETE)
      # lives in interpreter.nim; this just passes the flag through so the rule
      # actually fires.
      result.incl(sfConstScriptCode)
    of "TAPROOT": result.incl(sfTaproot)
    of "DISCOURAGE_UPGRADABLE_PUBKEYTYPE":
      result.incl(sfDiscourageUpgradablePubkeyType)
    of "DISCOURAGE_OP_SUCCESS": result.incl(sfDiscourageOpSuccess)
    of "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION":
      result.incl(sfDiscourageUpgradableTaprootVersion)
    else:
      raise newException(ValueError, "unknown flag token: " & name)

## Replicate Core's BuildCreditingTransaction (transaction_utils.cpp:10):
## version=1, locktime=0, one input with a null prevout (zero hash, n=0xFFFFFFFF)
## and scriptSig `OP_0 OP_0` (0x00 0x00), sequence 0xFFFFFFFF; one output with
## the test scriptPubKey + amount. No witnesses, so txid uses legacy
## serialization and matches Core's CTransaction::GetHash.
proc buildCreditingTx(scriptPubKey: seq[byte], amount: int64): Transaction =
  var nullTxid: array[32, byte]  # all zeros
  result.version = 1
  result.lockTime = 0
  result.inputs = @[TxIn(
    prevOut: OutPoint(txid: TxId(nullTxid), vout: 0xFFFFFFFF'u32),
    scriptSig: @[0x00'u8, 0x00'u8],
    sequence: 0xFFFFFFFF'u32
  )]
  result.outputs = @[TxOut(
    value: Satoshi(amount),
    scriptPubKey: scriptPubKey
  )]
  result.witnesses = @[]

## Replicate Core's BuildSpendingTransaction (transaction_utils.cpp:26):
## version=1, locktime=0, one input spending credit vout 0 with the test
## scriptSig + witness, sequence 0xFFFFFFFF; one empty-script output, same
## amount. Witness is stored per-input (witnesses[0]); only set if non-empty
## so legacy-tx serialization is preserved for non-witness rows.
proc buildSpendingTx(scriptSig: seq[byte], witness: seq[seq[byte]],
                     credit: Transaction): Transaction =
  result.version = 1
  result.lockTime = 0
  result.inputs = @[TxIn(
    prevOut: OutPoint(txid: credit.txid(), vout: 0'u32),
    scriptSig: scriptSig,
    sequence: 0xFFFFFFFF'u32
  )]
  result.outputs = @[TxOut(
    value: credit.outputs[0].value,
    scriptPubKey: @[]
  )]
  if witness.len > 0:
    result.witnesses = @[witness]
  else:
    result.witnesses = @[]

proc jsonEscape(s: string): string =
  result = ""
  for c in s:
    case c
    of '\\': result.add("\\\\")
    of '"': result.add("\\\"")
    of '\n': result.add("\\n")
    of '\r': result.add("\\r")
    of '\t': result.add("\\t")
    else: result.add(c)

proc processVerifyScript(req: JsonNode): string =
  let ssig = hexDecode(req["scriptSig_hex"].getStr())
  let spk = hexDecode(req["scriptPubKey_hex"].getStr())
  let amount = if req.hasKey("amount_sats"): req["amount_sats"].getBiggestInt()
               else: 0'i64

  var witness: seq[seq[byte]] = @[]
  if req.hasKey("witness") and req["witness"].kind == JArray:
    for w in req["witness"]:
      witness.add(hexDecode(w.getStr()))

  let flags = buildFlags(req["flags"])

  let credit = buildCreditingTx(spk, amount)
  let spend = buildSpendingTx(ssig, witness, credit)

  # Single-input prevout context for BIP-143/BIP-341 sighash.
  let allAmounts = @[Satoshi(amount)]
  let allScriptPubKeys = @[spk]

  let err = verifyScriptWithError(
    ssig, spk, spend, 0, Satoshi(amount), flags, witness,
    allAmounts, allScriptPubKeys
  )

  if err == seOk:
    result = """{"result":true}"""
  else:
    result = """{"result":false,"reason":"""" & jsonEscape($err) & "\"}"

## Convert a DISPLAY-ORDER txid hex (as given in the tx_*.json prevouts) to
## the wire-order TxId that nimrod's deserializer stores in OutPoint.txid.
## readTxId reads the 32 prevout bytes verbatim (little-endian / wire order);
## the JSON hex is the big-endian display string, so we hex-decode then
## reverse to match. (`$TxId` reverses on the way out, the mirror of this.)
proc txidFromDisplayHex(s: string): TxId =
  let raw = hexDecode(s)
  if raw.len != 32:
    raise newException(ValueError, "prevout txid not 32 bytes: " & $raw.len)
  var arr: array[32, byte]
  for i in 0 ..< 32:
    arr[i] = raw[31 - i]
  TxId(arr)

## Mirror Core's transaction_tests.cpp::CheckTxScripts over a REAL tx.
## Deserialize tx_hex with nimrod's own deserializer (handles the segwit
## marker/flag + per-input witnesses), build the prevout map, then run
## verifyScriptWithError per input with the sighash computed over THE REAL
## TX. Valid iff ALL inputs pass; reject on the FIRST failing input.
proc processVerifyTx(req: JsonNode): string =
  let txBytes = hexDecode(req["tx_hex"].getStr())
  let tx = deserializeTransaction(txBytes)

  let flags = buildFlags(req["flags"])

  # Prevout map keyed by (wire-order txid, vout). Both spk + amount.
  var spkMap = initTable[(TxId, uint32), seq[byte]]()
  var amtMap = initTable[(TxId, uint32), int64]()
  for p in req["prevouts"]:
    let txid = txidFromDisplayHex(p["txid"].getStr())
    let vout = uint32(p["vout"].getBiggestInt())
    let spk = hexDecode(p["scriptPubKey_hex"].getStr())
    # amount defaults to 0 when absent (Core: contains(prevout) ? at : 0).
    let amt = if p.hasKey("amount_sats"): p["amount_sats"].getBiggestInt()
              else: 0'i64
    spkMap[(txid, vout)] = spk
    amtMap[(txid, vout)] = amt

  # Assemble per-input spent-script / spent-amount vectors in the tx's own
  # input order, so the BIP-143/BIP-341 all-prevouts commitment lines up
  # with input i. A prevout missing from the map => malformed row => error
  # (the driver skips it; never a fake pass).
  let n = tx.inputs.len
  var spentScripts = newSeq[seq[byte]](n)
  var spentAmounts = newSeq[Satoshi](n)
  for i in 0 ..< n:
    let key = (tx.inputs[i].prevOut.txid, tx.inputs[i].prevOut.vout)
    if not spkMap.hasKey(key):
      raise newException(ValueError,
        "no prevout scriptPubKey for input " & $i & " " &
        $tx.inputs[i].prevOut.txid & ":" & $tx.inputs[i].prevOut.vout)
    spentScripts[i] = spkMap[key]
    spentAmounts[i] = Satoshi(amtMap.getOrDefault(key, 0'i64))

  # Per-input VerifyScript over the real tx. Reject on first failure,
  # matching Core's `i < vin.size() && tx_valid` short-circuit.
  for i in 0 ..< n:
    let ssig = tx.inputs[i].scriptSig
    let spk = spentScripts[i]
    let amount = spentAmounts[i]
    let witness = if i < tx.witnesses.len: tx.witnesses[i]
                  else: @[]
    let err = verifyScriptWithError(
      ssig, spk, tx, i, amount, flags, witness,
      spentAmounts, spentScripts
    )
    if err != seOk:
      return """{"valid":false,"reason":"""" &
        jsonEscape("input " & $i & ": " & $err) & "\"}"

  result = """{"valid":true}"""

## CheckTransaction-level (context-free, structural) validation. Mirrors
## bitcoin-core/src/consensus/tx_check.cpp::CheckTransaction by delegating
## to nimrod's OWN `checkTransaction` (src/consensus/validation.nim:1620),
## so a divergence here is a nimrod consensus bug, not a shim bug. No
## UTXO/chain state is needed — only the context-free gates G1..G9 run
## (vin/vout non-empty, oversize, output value range + running total,
## duplicate inputs, coinbase scriptSig length, non-coinbase null prevout).
## `params` is required by the signature but never read by those gates, so
## mainnetParams() is a placeholder.
proc processCheckTx(req: JsonNode): string =
  let txBytes = hexDecode(req["tx_hex"].getStr())
  let tx = deserializeTransaction(txBytes)
  let res = checkTransaction(tx, mainnetParams())
  if res.isOk:
    result = """{"valid":true}"""
  else:
    result = """{"valid":false,"reason":"""" &
      jsonEscape($res.error) & "\"}"

## Connect-time economic op `connecttx`. Drives nimrod's REAL connect-time
## Consensus::CheckTxInputs (bitcoin-core/src/consensus/tx_verify.cpp:164-214)
## by delegating to nimrod's OWN `validateTransaction`
## (src/consensus/validation.nim:727) — the proc connectBlock /
## connectBlockIBD call per non-coinbase tx (validation.nim:1249-1265,
## 1460-1502) to enforce the monetary rules. NOTHING here re-implements
## value-in>=out / maturity / missing; the shim only seeds the UTXO view and
## reports the impl's verdict.
##
## What validateTransaction enforces (= Core CheckTxInputs):
##   - missing/spent input  → veInputsMissing  (bad-txns-inputs-missingorspent)
##   - coinbase maturity 100 → veImmatureCoinbase (bad-txns-premature-spend-of-coinbase)
##   - per-input value MoneyRange → veBadAmount  (bad-txns-inputvalues-outofrange)
##   - running-sum input MoneyRange → veBadAmount (bad-txns-inputvalues-outofrange)
##   - no-inflation value-in>=value-out → veOutputsBelowInputs (bad-txns-in-belowout)
## It returns the fee on success. validateTransaction does NOT run script
## verification, so the economic verdict is isolated (no assumevalid wiring
## needed — a script failure cannot mask the monetary decision because the
## script is never evaluated on this path).
##
## validateTransaction omits Core's per-tx upper-bound fee check
## (`if (!MoneyRange(nFees))` → "bad-txns-fee-outofrange", tx_verify.cpp:208);
## we add that ONE explicit MoneyRange(fee) gate in the shim (a fee > MAX_MONEY
## can only arise from out-of-range inputs the impl already rejects, so this is
## a belt-and-suspenders gate, not a re-implementation of the economic rule).
##
##   request:  {"op":"connecttx","tx_hex":"<segwit-aware>",
##              "prevouts":[{"txid":"<DISPLAY-hex>","vout":N,
##                           "scriptPubKey_hex":"<spk>","value_sats":<i64>,
##                           "height":<int coin.nHeight>,
##                           "is_coinbase":<bool>},...],
##              "spend_height":<int nSpendHeight>}
##   response: {"valid":true,"fee_sats":<i64>}      (CheckTxInputs accepts)
##             {"valid":false,"reason":"bad-txns-*"} (CheckTxInputs rejects)
##             {"error":"..."}                       (cannot evaluate -> skip)
##
## An OMITTED prevout entry models a missing/spent input: the lookup closure
## returns none for that outpoint, and validateTransaction rejects with
## veInputsMissing exactly as ConnectBlock would on a missing coin.
proc processConnectTx(req: JsonNode): string =
  let txBytes = hexDecode(req["tx_hex"].getStr())
  let tx = deserializeTransaction(txBytes)
  let spendHeight = int32(req["spend_height"].getBiggestInt())

  # Seed the in-memory UTXO view: one coin per prevout entry, keyed by the
  # wire-order (txid, vout). Reuses the verifytx display->wire txid reversal.
  var view = initTable[(TxId, uint32), chainstate.UtxoEntry]()
  for p in req["prevouts"]:
    let txid = txidFromDisplayHex(p["txid"].getStr())
    let vout = uint32(p["vout"].getBiggestInt())
    let spk = hexDecode(p["scriptPubKey_hex"].getStr())
    let value = p["value_sats"].getBiggestInt()
    let coinHeight = int32(p["height"].getBiggestInt())
    let isCb = if p.hasKey("is_coinbase"): p["is_coinbase"].getBool() else: false
    view[(txid, vout)] = chainstate.UtxoEntry(
      output: TxOut(value: Satoshi(value), scriptPubKey: spk),
      height: coinHeight,
      isCoinbase: isCb
    )

  # Lookup closure over the seeded view. An outpoint NOT in the view => none
  # (missing/spent input), which validateTransaction rejects.
  let lookup = proc(op: OutPoint): Option[chainstate.UtxoEntry] =
    let key = (op.txid, op.vout)
    if view.hasKey(key):
      some(view[key])
    else:
      none(chainstate.UtxoEntry)

  # REAL connect-time economic check (validation.nim:727), at mainnet params
  # (coinbaseMaturity=100). Returns the fee on success.
  let res = validateTransaction(tx, lookup, spendHeight, mainnetParams())
  if not res.isOk:
    # Normalize the impl's enum string to a Core bad-txns-* token where the
    # mapping is unambiguous; the DECISION (valid=false) is what is scored.
    let reason = case res.error
      of veInputsMissing:     "bad-txns-inputs-missingorspent"
      of veImmatureCoinbase:  "bad-txns-premature-spend-of-coinbase"
      of veBadAmount:         "bad-txns-inputvalues-outofrange"
      of veOutputsBelowInputs:"bad-txns-in-belowout"
      else:                   $res.error
    return """{"valid":false,"reason":"""" & jsonEscape(reason) & "\"}"

  # Core tx_verify.cpp:208 per-tx fee upper bound (validateTransaction omits it).
  let fee = res.value
  if fee < 0'i64 or fee > int64(MaxMoney):
    return """{"valid":false,"reason":"bad-txns-fee-outofrange"}"""

  result = """{"valid":true,"fee_sats":""" & $fee & "}"

## PoW difficulty differential op `nextwork`. Drives nimrod's REAL
## src/consensus/pow.nim::getNextWorkRequired (the BlockIndex/chain-generic
## entrypoint that does the retarget math + the height%2016 off-by-one + the
## [timespan/4, timespan*4] clamp + the powLimit clamp + BIP94 anchoring),
## NOT a value-based or legacy twin.  Mirrors how validation.nim:858-896
## builds the call (PowParams field-copy from getParams(network), a pow.
## BlockIndex for the previous block, and a getAncestor closure).
##
##   request:  {"op":"nextwork","network":"mainnet","height":<H>,
##              "block_time":<u32>,
##              "last":{"height":<int>,"bits":"<8hex>","time":<u32>},
##              "first":{"height":<int>,"bits":"<8hex>","time":<u32>}}
##              ("first" present ONLY on retarget boundaries, H%2016==0)
##   response: {"nbits":"<8hex>"}   (impl's REAL computed required nBits)
##             {"error":"..."}      (cannot compute -> driver skips)
##
## bits are 8-lowercase-hex (Core getblockheader format); nimrod stores nBits
## as uint32, so we parse on entry and format on exit.

## Map the network token to nimrod's params.Network enum (mirrors getParams
## input).  Unknown token -> raise (shim emits {"error":...}; driver skips).
proc networkFromToken(name: string): Network =
  case name
  of "mainnet": Mainnet
  of "testnet3": Testnet3
  of "testnet4": Testnet4
  of "regtest": Regtest
  of "signet": Signet
  else: raise newException(ValueError, "unknown network: " & name)

## Parse an 8-hex Core-format nBits string into the uint32 nimrod stores.
proc parseBits(s: string): uint32 =
  if s.len != 8:
    raise newException(ValueError, "bits not 8 hex chars: " & s)
  uint32(parseHexInt(s))

## Format a uint32 nBits back to 8-lowercase-hex (Core getblockheader format).
proc formatBits(b: uint32): string =
  toLowerAscii(toHex(b, 8))

## Build a pow.BlockIndex from a JSON {"height","bits","time"} node.  Only the
## fields getNextWorkRequired reads are populated: height, header.timestamp,
## header.bits.  prevBlock/hash are left default — getAncestor here is a
## height-keyed closure over (last, first), so prevHash links are never walked.
proc powIndexFromJson(node: JsonNode): pow.BlockIndex =
  result = pow.BlockIndex(
    height: int32(node["height"].getBiggestInt()),
    hash: default(BlockHash)
  )
  result.header = default(BlockHeader)
  result.header.timestamp = uint32(node["time"].getBiggestInt())
  result.header.bits = parseBits(node["bits"].getStr())

proc processNextWork(req: JsonNode): string =
  let network = networkFromToken(req["network"].getStr())
  let blockTime = uint32(req["block_time"].getBiggestInt())

  # Field-copy ConsensusParams -> pow.PowParams (validation.nim:880-894).
  let cp = getParams(network)
  let powNetwork: pow.NetworkKind = case cp.network
    of Mainnet:  pow.Mainnet
    of Testnet3: pow.Testnet3
    of Testnet4: pow.Testnet4
    of Regtest:  pow.Regtest
    of Signet:   pow.Signet
  let powParams = pow.PowParams(
    network:                     powNetwork,
    powLimit:                    cp.powLimit,
    powTargetTimespan:           cp.powTargetTimespan,
    powTargetSpacing:            cp.powTargetSpacing,
    powAllowMinDifficultyBlocks: cp.powAllowMinDifficultyBlocks,
    powNoRetargeting:            cp.powNoRetargeting,
    enforceBIP94:                cp.enforceBIP94
  )

  # pindexLast = the tip the next block is solved on (= request "last").
  let lastIndex = powIndexFromJson(req["last"])

  # getAncestor: a height-keyed closure over the (last, first) 2-node chain.
  # On a retarget boundary getNextWorkRequired asks for height
  # (last.height - 2015) == first.height, which must resolve to "first".
  # On passthrough rows mainnet never calls getAncestor (returns last.bits),
  # but testnet min-diff can walk back; we serve "last" for its own height and
  # "first" for first's height, and raise for any other height so a wrong
  # ancestor request surfaces as {"error":...} (driver skips) rather than a
  # silently-faked value.
  var firstIndex: pow.BlockIndex
  let haveFirst = req.hasKey("first") and req["first"].kind == JObject
  if haveFirst:
    firstIndex = powIndexFromJson(req["first"])

  let lastH = lastIndex.height
  let firstH = if haveFirst: firstIndex.height else: int32.low
  let lastIdxCap = lastIndex
  let firstIdxCap = firstIndex
  let getAncestor = proc(idx: pow.BlockIndex, height: int32): pow.BlockIndex =
    if height == lastH:
      lastIdxCap
    elif haveFirst and height == firstH:
      firstIdxCap
    else:
      raise newException(ValueError,
        "getAncestor: no node at height " & $height &
        " (have last=" & $lastH & (if haveFirst: ", first=" & $firstH else: "") & ")")

  let nbits = pow.getNextWorkRequired(lastIndex, blockTime, powParams, getAncestor)
  result = """{"nbits":"""" & formatBits(nbits) & "\"}"

## Merkle-root differential op `merkleroot` (CVE-2012-2459).
## Drives nimrod's REAL tx-merkle primitive
## (src/consensus/validation.nim:175 computeMerkleRoot), which builds the
## root with Bitcoin's duplicate-last-if-odd rule.
##
## txids arrive in DISPLAY order (Core getblock convention, big-endian); the
## impl merkle code works on internal/wire byte order, so each txid is
## hex-decoded then reversed (the SAME display->wire reversal `verifytx`
## applies via txidFromDisplayHex). The computed internal root is reversed
## back to display order so it matches Core's header `merkleroot`.
##
## CRITICAL — mutated reflects nimrod's TRUE block-acceptance behavior:
## nimrod's REAL merkle primitive now carries CVE-2012-2459 detection via
## computeMerkleRootMutated (src/consensus/validation.nim — Core's
## adjacent-pair-equal scan at the TOP of each level, BEFORE the odd-tail
## duplication, complete pairs only). checkBlock / validateBlock reject a
## mutated block with veMutatedMerkleTree (bad-txns-duplicate), so this op
## reports the REAL `mutated` returned by the impl primitive — NOT a faked
## value and NOT a check re-implemented in the shim. Honest odd-N blocks stay
## mutated=false; cve2459 duplicate-tx constructions report mutated=true.
##
##   request:  {"op":"merkleroot","txids":["<64-hex display>",...]}
##   response: {"root":"<64-hex display>","mutated":<bool>}
##             {"error":"..."}   (cannot compute -> driver skips)

## Reverse a DISPLAY-ORDER (big-endian) 32-byte hex txid to internal/wire
## byte order, returning array[32,byte] for computeMerkleRoot. Same reversal
## as txidFromDisplayHex (which wraps the result in TxId for OutPoint).
proc internalHashFromDisplayHex(s: string): array[32, byte] =
  let raw = hexDecode(s)
  if raw.len != 32:
    raise newException(ValueError, "txid not 32 bytes: " & $raw.len)
  for i in 0 ..< 32:
    result[i] = raw[31 - i]

## Format an internal/wire 32-byte hash back to DISPLAY-ORDER hex (mirror of
## internalHashFromDisplayHex; same convention as `$TxId` in types.nim which
## emits bytes 31..0).
proc displayHexFromInternalHash(h: array[32, byte]): string =
  result = ""
  for i in countdown(31, 0):
    result.add(toHex(h[i], 2).toLowerAscii)

proc processMerkleRoot(req: JsonNode): string =
  var hashes: seq[array[32, byte]] = @[]
  for t in req["txids"]:
    hashes.add(internalHashFromDisplayHex(t.getStr()))
  if hashes.len == 0:
    raise newException(ValueError, "empty txids")

  # nimrod's REAL merkle primitive WITH CVE-2012-2459 mutation detection. The
  # same computeMerkleRootMutated drives checkBlock / validateBlock, which
  # reject a mutated block (veMutatedMerkleTree / bad-txns-duplicate).
  var mutated = false
  let internalRoot = computeMerkleRootMutated(hashes, mutated)
  let displayRoot = displayHexFromInternalHash(internalRoot)

  let mutatedStr = if mutated: "true" else: "false"
  result = """{"root":"""" & displayRoot & """","mutated":""" & mutatedStr & "}"

## Block-subsidy differential op `subsidy`. Drives nimrod's REAL PRIMARY
## consensus subsidy fn (src/consensus/validation.nim:256
## getBlockSubsidy(height: int32, params)) — the one block validation /
## ConnectBlock uses for the coinbase cap — at MAINNET params (halving
## interval 210000). A SECOND def exists at params.nim:533; this op
## deliberately drives the validation one so the differential catches a
## disagreement (halving-boundary off-by-one, missing >=64 zero-guard).
## The halving schedule is NOT re-implemented in the shim.
##
##   request:  {"op":"subsidy","height":<int>}
##   response: {"subsidy_sats":<int>}   (impl's REAL subsidy in satoshis)
##             {"error":"..."}          (cannot compute -> driver skips)
proc processSubsidy(req: JsonNode): string =
  let height = int32(req["height"].getBiggestInt())
  let subsidy = validation.getBlockSubsidy(height, mainnetParams())
  result = """{"subsidy_sats":""" & $int64(subsidy) & "}"

proc process(line: string): string =
  let req = parseJson(line)
  let op = if req.hasKey("op"): req["op"].getStr() else: "verifyscript"
  case op
  of "verifyscript": processVerifyScript(req)
  of "verifytx": processVerifyTx(req)
  of "checktx": processCheckTx(req)
  of "connecttx": processConnectTx(req)
  of "nextwork": processNextWork(req)
  of "merkleroot": processMerkleRoot(req)
  of "subsidy": processSubsidy(req)
  else: raise newException(ValueError, "unknown op: " & op)

proc main() =
  var line: string
  while stdin.readLine(line):
    if line.strip().len == 0:
      continue
    var resp: string
    try:
      resp = process(line)
    except CatchableError as e:
      resp = """{"error":"""" & jsonEscape(e.msg) & "\"}"
    stdout.writeLine(resp)
    stdout.flushFile()

when isMainModule:
  main()
