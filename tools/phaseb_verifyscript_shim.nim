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

import std/[json, strutils, tables, options, os, algorithm, times, random]
import ../src/primitives/types
import ../src/primitives/serialize
import ../src/script/interpreter
import ../src/consensus/validation
import ../src/consensus/params
import ../src/storage/chainstate
import ../src/consensus/chain
import ../src/consensus/pow
import ../src/crypto/secp256k1
import ../src/crypto/hashing

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

## VALIDATE-ONLY block differential op `checkblock`. Drives nimrod's REAL
## block-acceptance gates — CheckBlock (context-free) + ContextualCheckBlock
## + ConnectBlock (monetary / sigops / weight / witness-commitment / BIP-34
## coinbase height) + per-input VerifyScript — over a FINAL (already-mutated)
## block_hex, validating it AS-IS (we never recompute the merkle root or
## re-derive the witness commitment; the mutated bytes are taken verbatim so a
## merkle/witness mutation is actually caught by the impl's own gate).
##
## Pipeline:  deserializeBlock(block_hex)
##              -> validateBlock(blk, prevIndex, db, mainnetParams(),
##                               checkScripts=false, checkPow=!skip_pow,
##                               getUtxoOverride=seeded-view)
##              -> (if not skip_scripts) verifyScripts(blk, seeded-view, ...)
##
## WHY validateBlock DIRECTLY and NOT acceptBlock: acceptBlock step 1 re-runs
## the context-free checkBlock(), whose checkBlockHeader() ALWAYS verifies the
## PoW hash regardless of any flag (validation.nim:1899 -> 1648). The corpus
## block_hex is FINAL/mutated and misses the mainnet PoW target, so routing
## through acceptBlock would make every mutant reject on "high-hash" — a SILENT
## DEAD-GATE. validateBlock's header step (validateBlockHeader) takes checkPow
## as a parameter and skips the hash-meets-target gate when false, while still
## running merkle / weight / coinbase / witness / per-tx / sigop / monetary
## gates. This is exactly Core's CheckBlock(fCheckPOW=false) usage (the corpus
## sets skip_pow=true). With checkPow=false getNextWorkRequired returns the
## prev block's bits without an ancestor walk (709742 is not a retarget
## boundary, mainnet powAllowMinDifficultyBlocks=false), so no deep chain
## window is required for the bad-diffbits gate.
##
## UTXO view: one coin per prevout entry, keyed by wire-order (txid, vout)
## using the SAME txidFromDisplayHex display->wire reversal + the SAME
## Table[(TxId,uint32),UtxoEntry] + lookup-closure-returns-none-for-omitted
## plumbing as `connecttx` (processConnectTx above). An omitted prevout models
## a missing/spent input. The closure is wired into BOTH validateBlock
## (getUtxoOverride, for fee/sigop/BIP68 reads) and verifyScripts (for script
## input lookups), so the two stages see the identical seeded view.
##
## prevIndex / ChainDb: built via the OBJECT CTOR (NOT openChainDb, which would
## hit disk). prevIndex carries height = spend_height - 1, hash = the block's
## OWN header.prevBlock (already wire-order from the deserializer), and a header
## whose `bits` equal the block's nBits (so the non-retarget bad-diffbits gate
## passes for the real block) and a `timestamp` strictly below the block time
## (so the MTP time-too-old gate passes). The ChainDb's ibdIndexBy{Hash,Height}
## shadow maps are populated with a HASH-LINKED synthetic prev window so
## getMtpForBlockIndex (the hash-linked parent walk validateBlock/
## contextualCheckBlockHeader use since adf1ef2, NOT the old height-indexed
## getMtpForHeight) stays entirely inside the in-memory shadow and never
## dereferences the nil `db` handle.
##
##   request:  {"op":"checkblock","block_hex":"<FINAL bytes>",
##              "prevouts":[{"txid":"<DISPLAY-hex>","vout":N,
##                           "scriptPubKey_hex":"<spk>","value_sats":<u64>,
##                           "height":<int>,"is_coinbase":<bool>},...one per
##                          NON-COINBASE input across all non-coinbase txs],
##              "spend_height":<int>,"skip_pow":<bool>,"skip_scripts":<bool>}
##   response: {"valid":true}                          (block accepted)
##             {"valid":false,"reason":"<bad-* token>"} (a gate rejected)
##             {"error":"..."}                          (cannot evaluate)
proc processCheckBlock(req: JsonNode): string =
  let blockBytes = hexDecode(req["block_hex"].getStr())
  let blk = deserializeBlock(blockBytes)
  let spendHeight = int32(req["spend_height"].getBiggestInt())
  let skipPow = if req.hasKey("skip_pow"): req["skip_pow"].getBool() else: true
  let skipScripts = if req.hasKey("skip_scripts"): req["skip_scripts"].getBool()
                    else: false

  # Seed the in-memory UTXO view — one coin per prevout, keyed by wire-order
  # (txid, vout). Identical plumbing to processConnectTx (display->wire
  # reversal via txidFromDisplayHex).
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

  # Lookup closure over the seeded view. Outpoint NOT in view => none
  # (missing/spent input). gcsafe/raises:[] to match validateBlock's
  # getUtxoOverride signature; the try/except satisfies raises:[] (Table.[]
  # is raises:[KeyError]) and only ever wraps a successful hasKey hit.
  let lookup = proc(op: OutPoint): Option[chainstate.UtxoEntry] {.gcsafe, raises: [].} =
    let key = (op.txid, op.vout)
    if view.hasKey(key):
      try: some(view[key])
      except KeyError: none(chainstate.UtxoEntry)
    else:
      none(chainstate.UtxoEntry)

  let params = mainnetParams()
  let prevHeight = spendHeight - 1

  # prevIndex: hash = the block's OWN header.prevBlock (wire-order from the
  # deserializer, so validateBlockHeader's prevBlock-link check passes). bits =
  # the block's nBits (non-retarget => getNextWorkRequired returns this, so the
  # bad-diffbits gate passes). timestamp = one below the block time so the MTP
  # gate (single-window fallback) accepts.
  # Deterministic synthetic hash per height for the hash-linked shadow window
  # (below). The prevHeight slot reuses the block's real prevBlock so it also
  # backs the prevIndex link; every other height is height-tagged.
  proc synthHash(hh: int32): array[32, byte] =
    if hh == prevHeight:
      return array[32, byte](blk.header.prevBlock)
    result[0] = byte(hh and 0xff)
    result[1] = byte((hh shr 8) and 0xff)
    result[2] = byte((hh shr 16) and 0xff)
    result[3] = byte((hh shr 24) and 0xff)
  var prevHeader = default(BlockHeader)
  prevHeader.bits = blk.header.bits
  prevHeader.timestamp = (if blk.header.timestamp > 0'u32: blk.header.timestamp - 1'u32
                          else: 0'u32)
  # Hash-link prevIndex to its synthetic parent so getMtpForBlockIndex's
  # parent-hash walk resolves inside the shadow (adf1ef2 switched the MTP source
  # from height-indexed getMtpForHeight to hash-linked getMtpForBlockIndex).
  prevHeader.prevBlock = BlockHash(synthHash(prevHeight - 1))
  let prevIndex = chainstate.BlockIndex(
    hash: blk.header.prevBlock,
    height: prevHeight,
    header: prevHeader,
    prevHash: default(BlockHash)
  )

  # ChainDb via the OBJECT CTOR (no disk). db left nil; the ibd shadow maps are
  # populated so every getMtpForBlockIndex read stays in-memory and never touches
  # the nil db handle. Seed a HASH-LINKED synthetic window (MedianTimeSpan+2 deep)
  # with strictly-increasing timestamps all below the block time. Each header's
  # prevBlock points at the next-lower synthetic hash so getMtpForBlockIndex's
  # parent-hash walk completes entirely inside the shadow; the deepest slot
  # self-links so a walk one hop past the window still resolves in-memory.
  let db = ChainDb(
    db: nil,
    bestBlockHash: blk.header.prevBlock,
    bestHeight: prevHeight,
    ibdIndexByHash: initTable[BlockHash, chainstate.BlockIndex](),
    ibdIndexByHeight: initTable[int32, BlockHash]()
  )
  block seedWindow:
    let baseTime = prevHeader.timestamp
    let windowDepth = MedianTimeSpan + 2
    for off in 0 ..< windowDepth:
      let h = prevHeight - int32(off)
      if h < 0: break
      let bh = BlockHash(synthHash(h))
      var wh = default(BlockHeader)
      wh.bits = blk.header.bits
      # Earlier heights get earlier timestamps so MTP < block time.
      wh.timestamp = if baseTime >= uint32(off): baseTime - uint32(off) else: 0'u32
      # Hash-link to the synthetic parent so getMtpForBlockIndex stays in-shadow;
      # deepest slot self-links so an extra hop never derefs the nil db handle.
      if off == windowDepth - 1 or h - 1 < 0:
        wh.prevBlock = bh
      else:
        wh.prevBlock = BlockHash(synthHash(h - 1))
      db.ibdIndexByHash[bh] = chainstate.BlockIndex(hash: bh, height: h, header: wh)
      db.ibdIndexByHeight[h] = bh

  # Step 1+2+3: CheckBlock (context-free) + ContextualCheckBlock + the
  # ConnectBlock monetary/sigop/weight/witness gates, all inside validateBlock.
  # checkScripts=false here (scripts run in step 4); checkPow=!skip_pow so the
  # PoW hash gate is skipped exactly when the corpus asks (no high-hash on a
  # body mutant => no silent dead-gate).
  let vres = validateBlock(blk, prevIndex, db, params,
                           checkScripts = false,
                           checkPow = not skipPow,
                           getUtxoOverride = lookup)
  if not vres.isOk:
    return """{"valid":false,"reason":"""" &
      jsonEscape(bip22String(vres.error)) & "\"}"

  # Step 4: REAL per-input script verification (skip_scripts=false). Uses the
  # SAME seeded view. verifyScripts returns veScriptVerifyFailed on the first
  # failing input -> "block-script-verify-flag-failed".
  if not skipScripts:
    var crypto = newCryptoEngine()
    defer: crypto.close()
    let sres = verifyScripts(blk, lookup, spendHeight, crypto, params)
    if not sres.isOk:
      return """{"valid":false,"reason":"""" &
        jsonEscape(bip22String(sres.error)) & "\"}"

  result = """{"valid":true}"""

## BIP-30 dup-txid / coin-overwrite op `checkbip30` (CVE-2012-1909).
## Drives nimrod's REAL `checkBip30` (src/consensus/validation.nim:1829) — the
## EXACT proc acceptBlock step 3 (validation.nim:2086) calls — over a seeded
## UTXO view, NOT a reimplementation in the shim.
##
## WHY a dedicated op and NOT the committed `checkblock` op: `checkblock` drives
## `validateBlock` DIRECTLY (validation.nim:2067-2070, checkScripts=false), and
## nimrod's BIP-30 gate lives in `acceptBlock` step 3 — OUTSIDE validateBlock
## (validateBlock = the contextual header + weight + sigops + BIP-34-height +
## coinbase-value gates; checkBip30 is a separate step). Routing the BIP-30
## vectors through `checkblock` would NOT exercise checkBip30 at all (the
## collision would slip past validateBlock and the block would falsely accept).
## So this op isolates and drives checkBip30 over the seeded view exactly as
## ConnectBlock's HaveCoin loop does (validation.cpp:2467-2475).
##
## Mirrors the rustoshi `checkblock` BIP-30 loop (validation.rs:1684) which
## scans every block-tx output for an existing unspent coin. The coinbase txid
## T = doubleSha256(non-witness coinbase bytes) is computed by nimrod's OWN
## `tx.txid()` inside checkBip30 — so the collision key matches byte-for-byte
## with the seeded (T,0) coin (the corpus T is the impl-agnostic dbl-sha256).
##
## Decision-first scoring + ANTI-MASKING: checkBip30 only ever returns ok()
## (accept) or veBip30DuplicateOutput (=> "bad-txns-BIP30"). There is no
## structural / missing-input gate on this path, so a reject here CANNOT be
## masked by anything other than the BIP-30 gate itself. P1 (byte-identical
## block, no (T,0) seed) accepts because the HaveCoin scan finds nothing; if P1
## rejected it would prove the seeding leaked into the no-seed case.
##
## BIP-34 short-circuit (N1): checkBip30 clears fEnforceBIP30 when
## height >= params.bip34Height (mainnet 227931) and height < 1_983_702 and
## params.bip34Hash is non-zero (mainnet IS non-zero, params.nim:170), then
## returns ok() WITHOUT scanning — so a post-BIP34 collision (h=400000) accepts.
## This is nimrod's REAL Gate 2/3 logic; over-enforcing here (rejecting N1)
## would be a real missing-short-circuit bug.
##
## The block hash fed to Gate 1 (IsBIP30Repeat) is doubleSha256(serialize(
## blk.header)) — nimrod's own header serializer + hasher — so the historical
## h=91842/h=91880 exemption is keyed on the REAL block hash, not a faked one.
## The corpus blocks are at h=91000 / h=400000 with zero prevBlock, so they are
## NOT the historical exempt blocks and Gate 1 never fires for them.
##
##   request:  {"op":"checkbip30","block_hex":"<FINAL bytes>",
##              "prevouts":[{"txid":"<DISPLAY-hex>","vout":N,
##                           "scriptPubKey_hex":"<spk>","value_sats":<i64>,
##                           "height":<int>,"is_coinbase":<bool>},...the seeded
##                          (T,0) collision coin (R1/N1) or empty (P1)],
##              "spend_height":<int = the block height>}
##   response: {"valid":true}                          (BIP-30 accepts)
##             {"valid":false,"reason":"bad-txns-BIP30"} (collision rejected)
##             {"error":"..."}                          (cannot evaluate)
proc processCheckBip30(req: JsonNode): string =
  let blockBytes = hexDecode(req["block_hex"].getStr())
  let blk = deserializeBlock(blockBytes)
  let height = int32(req["spend_height"].getBiggestInt())

  # Seed the in-memory UTXO view — one coin per prevout, keyed by wire-order
  # (txid, vout). Identical display->wire reversal + Table plumbing as
  # processConnectTx / processCheckBlock. The seeded (T,0) coin models a prior
  # block having created the coinbase output that this block's coinbase would
  # overwrite — the exact CVE-2012-1909 collision.
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

  # hasUtxo closure over the seeded view (the bool signature checkBip30 wants).
  # Outpoint NOT in view => false (no collision). gcsafe/raises:[] to match the
  # checkBip30 hasUtxo signature; the try/except satisfies raises:[].
  let hasUtxo = proc(op: OutPoint): bool {.gcsafe, raises: [].} =
    let key = (op.txid, op.vout)
    if view.hasKey(key):
      try: view.hasKey(key)
      except KeyError: false
    else:
      false

  # Block hash for Gate 1 (IsBIP30Repeat): nimrod's OWN header serializer +
  # doubleSha256 (the SAME computation acceptBlock step 3 uses, validation.nim
  # :2077-2078). Never a faked hash.
  let blkHeaderBytes = serialize(blk.header)
  let blkHashArr = array[32, byte](doubleSha256(blkHeaderBytes))

  # Drive nimrod's REAL checkBip30 over the seeded view at mainnet params
  # (bip34Height=227931, bip34Hash non-zero) so the BIP-34 short-circuit fires
  # for post-BIP34 heights exactly as Core does.
  let res = checkBip30(blk, height, blkHashArr, mainnetParams(), hasUtxo)
  if not res.isOk:
    return """{"valid":false,"reason":"""" &
      jsonEscape(bip22String(res.error)) & "\"}"
  result = """{"valid":true}"""

## DETERMINISTIC REORG op `reorg`. Drives nimrod's REAL reorg primitives over
## an EXPLICIT decision + coins-view + per-block undo, eliminating the live-tip /
## first-seen / nSequenceId race the old submitblock harness suffered from:
##
##   (1) WORK-COMPARE — strict new>old via nimrod's OWN pure 256-bit comparator
##       chain.compareWork256 (src/consensus/chain.nim:137). The request supplies
##       BE-256 hex; compareWork256 expects LITTLE-endian byte arrays, so each is
##       reversed BE->LE before the call. new<=old => no-reorg-equal-or-less-work,
##       view untouched (the side branch is NEVER evaluated).
##
##   (2) DEPTH CAP — disconnect.len > MAX_REORG_DEPTH(=100, chainstate.nim:1922)
##       => reorg-too-deep, mirroring handleReorg's guard. EXPECTED-DIVERGENCE
##       vs Core (Core has no fixed cap).
##
##   (3) DISCONNECT — per disconnect block tip-first, drive nimrod's REAL
##       chainstate.disconnectBlock(cs, blk, height, undo, fClean) over a REAL
##       ChainState backed by a throwaway temp RocksDB seeded with the
##       pre-disconnect (working) coins-view. The 4-field coin-identity / HaveCoin
##       unclean signal is surfaced via the fClean out-param wired into the REAL
##       DisconnectBlock (validation.cpp:2185-2244 DISCONNECT_UNCLEAN). BIP-30
##       h=91722/91812 exemption is handled inside disconnectBlock. unclean is
##       non-fatal (Core parity) — the reorg still applies.
##
##   (4) CONNECT — per connect block in order, drive nimrod's REAL FULL
##       re-validation at THAT block's OWN height: validateBlock(checkScripts=
##       false, checkPow=false) [CheckBlock + ContextualCheckBlock + the
##       ConnectBlock monetary/sigop/weight/coinbase-value gates] + verifyScripts
##       [per-input script verification with getBlockScriptFlags(height) — flags
##       ON, derived from the block's own height]. This is the SAME primitive the
##       committed `checkblock` op proves. Stop at the FIRST reject
##       (connected_count = blocks that passed before it). The post-disconnect
##       coins-view is threaded between connect blocks so input/double-spend
##       resolution is correct (R2 double-spend, R6 maturity).
##
## digest = sha256 over the sorted canonical coins-view (sort by wire-txid then
## vout; per coin: txid[32] || vout u32 LE || height u32 LE || is_coinbase u8 ||
## value u64 LE || spk_len u32 LE || spk). Decision-first scoring tolerates digest
## divergence on reject vectors.
##
##   request:  {"op":"reorg","network":"regtest"|"mainnet",
##              "fork_utxo":[{coin}...],            # the WORKING coins-view
##              "disconnect":[{block_hex,height,undo:[{tx_index,vin:[coin]}]}...],
##              "connect":[{block_hex,height,prev_mtp}...],
##              "old_tip_work_hex":<32B BE hex>,"new_tip_work_hex":<32B BE hex>}
##   response: {"outcome":...,"disconnect_result":...,"connected_count":N,
##              "reject_reason":<token>,"fork_utxo_digest":<sha256 hex>}
##             {"error":...}

type ShimCoin = object
  spk: seq[byte]
  value: int64
  height: int32
  isCoinbase: bool

proc coinFromJson(j: JsonNode): (TxId, uint32, ShimCoin) =
  let txid = txidFromDisplayHex(j["txid"].getStr())
  let vout = uint32(j["vout"].getBiggestInt())
  let c = ShimCoin(
    spk: hexDecode(j["scriptPubKey_hex"].getStr()),
    value: j["value_sats"].getBiggestInt(),
    height: int32(j["height"].getBiggestInt()),
    isCoinbase: (if j.hasKey("is_coinbase"): j["is_coinbase"].getBool() else: false)
  )
  (txid, vout, c)

## sha256 over the sorted canonical coins-view, byte-identical to the rustoshi
## driver's view_digest (tools/phaseb-vectors/reorg_vectors.py).
proc viewDigest(view: Table[(TxId, uint32), ShimCoin]): string =
  var keys: seq[(TxId, uint32)] = @[]
  for k in view.keys: keys.add(k)
  # sort by (wire-txid bytes ascending, then vout ascending)
  keys.sort(proc(a, b: (TxId, uint32)): int =
    let aw = array[32, byte](a[0])
    let bw = array[32, byte](b[0])
    for i in 0 ..< 32:
      if aw[i] < bw[i]: return -1
      elif aw[i] > bw[i]: return 1
    if a[1] < b[1]: return -1
    elif a[1] > b[1]: return 1
    0)
  var buf: seq[byte] = @[]
  for k in keys:
    let c = view[k]
    let w = array[32, byte](k[0])
    for b in w: buf.add(b)
    # vout u32 LE
    buf.add(byte(k[1] and 0xff)); buf.add(byte((k[1] shr 8) and 0xff))
    buf.add(byte((k[1] shr 16) and 0xff)); buf.add(byte((k[1] shr 24) and 0xff))
    # height u32 LE
    let h = uint32(c.height)
    buf.add(byte(h and 0xff)); buf.add(byte((h shr 8) and 0xff))
    buf.add(byte((h shr 16) and 0xff)); buf.add(byte((h shr 24) and 0xff))
    # is_coinbase u8
    buf.add(if c.isCoinbase: 1'u8 else: 0'u8)
    # value u64 LE
    let v = uint64(c.value)
    for s in 0 ..< 8: buf.add(byte((v shr (s*8)) and 0xff))
    # spk_len u32 LE
    let sl = uint32(c.spk.len)
    buf.add(byte(sl and 0xff)); buf.add(byte((sl shr 8) and 0xff))
    buf.add(byte((sl shr 16) and 0xff)); buf.add(byte((sl shr 24) and 0xff))
    for b in c.spk: buf.add(b)
  let d = sha256Single(buf)
  result = ""
  for b in d: result.add(toHex(b, 2).toLowerAscii)

## Reverse a 32-byte BE hex work string into the little-endian array
## chain.compareWork256 expects (countdown(31,0) => index 31 is MSB => LE).
proc workLEfromBEHex(s: string): array[32, byte] =
  let raw = hexDecode(s)
  if raw.len != 32:
    raise newException(ValueError, "work hex not 32 bytes: " & $raw.len)
  for i in 0 ..< 32:
    result[i] = raw[31 - i]

## Run nimrod's REAL FULL block re-validation (validateBlock checkScripts=false,
## checkPow=false + verifyScripts) over an explicit coins-view lookup, at the
## block's OWN height. Returns "" on accept, else the canonical reject token.
## Mirrors processCheckBlock's prev-window / ChainDb-shadow seeding so contextual
## gates (MTP, bad-diffbits) stay in-memory and never touch a nil db handle.
proc revalidateConnectBlock(blk: Block, spendHeight: int32,
                            params: ConsensusParams,
                            lookup: proc(op: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].}): string =
  let prevHeight = spendHeight - 1
  # Choose the prev (tip) timestamp comfortably MORE than 2*powTargetSpacing
  # below the block time. On regtest powAllowMinDifficultyBlocks=true, so
  # pow.getNextWorkRequired takes the min-difficulty shortcut (pow.nim:152)
  # `blockTime > lastTime + 2*spacing => return powLimitCompact` and never
  # enters the walk-back loop (pow.nim:157-161), which on a synthetic prev
  # window with no deeper ancestors would not terminate. The block's own bits
  # equal powLimitCompact on regtest, so bad-diffbits still passes. Each earlier
  # window block is spaced one second lower so MTP stays below the block time.
  let gap = uint32(2 * params.powTargetSpacing + 1)
  let baseTime = if blk.header.timestamp > gap: blk.header.timestamp - gap else: 0'u32
  # Deterministic synthetic hash per height for the hash-linked shadow window
  # (below); prevHeight slot reuses the block's real prevBlock, others height-tagged.
  proc synthHash(ht: int32): array[32, byte] =
    if ht == prevHeight:
      return array[32, byte](blk.header.prevBlock)
    result[0] = byte(ht and 0xff)
    result[1] = byte((ht shr 8) and 0xff)
    result[2] = byte((ht shr 16) and 0xff)
    result[3] = byte((ht shr 24) and 0xff)
  var prevHeader = default(BlockHeader)
  prevHeader.bits = blk.header.bits
  prevHeader.timestamp = baseTime
  # Hash-link prevIndex to its synthetic parent so getMtpForBlockIndex's
  # parent-hash walk resolves inside the shadow (adf1ef2: hash-linked MTP walk).
  prevHeader.prevBlock = BlockHash(synthHash(prevHeight - 1))
  let prevIndex = chainstate.BlockIndex(
    hash: blk.header.prevBlock,
    height: prevHeight,
    header: prevHeader,
    prevHash: default(BlockHash)
  )
  let db = ChainDb(
    db: nil,
    bestBlockHash: blk.header.prevBlock,
    bestHeight: prevHeight,
    ibdIndexByHash: initTable[BlockHash, chainstate.BlockIndex](),
    ibdIndexByHeight: initTable[int32, BlockHash]()
  )
  block seedWindow:
    let windowDepth = MedianTimeSpan + 2
    for off in 0 ..< windowDepth:
      let hh = prevHeight - int32(off)
      if hh < 0: break
      let bh = BlockHash(synthHash(hh))
      var wh = default(BlockHeader)
      wh.bits = blk.header.bits
      wh.timestamp = if baseTime >= uint32(off): baseTime - uint32(off) else: 0'u32
      # Hash-link to the synthetic parent so getMtpForBlockIndex stays in-shadow;
      # deepest slot self-links so an extra hop never derefs the nil db handle.
      if off == windowDepth - 1 or hh - 1 < 0:
        wh.prevBlock = bh
      else:
        wh.prevBlock = BlockHash(synthHash(hh - 1))
      db.ibdIndexByHash[bh] = chainstate.BlockIndex(hash: bh, height: hh, header: wh)
      db.ibdIndexByHeight[hh] = bh

  let vres = validateBlock(blk, prevIndex, db, params,
                           checkScripts = false, checkPow = false,
                           getUtxoOverride = lookup)
  if not vres.isOk:
    return bip22String(vres.error)
  var crypto = newCryptoEngine()
  defer: crypto.close()
  let sres = verifyScripts(blk, lookup, spendHeight, crypto, params)
  if not sres.isOk:
    return bip22String(sres.error)
  ""

proc processReorg(req: JsonNode): string =
  let params = case req["network"].getStr()
    of "mainnet": mainnetParams()
    of "regtest": regtestParams()
    of "testnet4": testnet4Params()
    else: raise newException(ValueError, "unknown network: " & req["network"].getStr())

  # --- the explicit working coins-view (shim-threaded, for digest + connect) ---
  var view = initTable[(TxId, uint32), ShimCoin]()
  if req.hasKey("fork_utxo"):
    for j in req["fork_utxo"]:
      let (txid, vout, c) = coinFromJson(j)
      view[(txid, vout)] = c

  # ===== (1) WORK-COMPARE via nimrod's REAL pure comparator =====
  let oldW = workLEfromBEHex(req["old_tip_work_hex"].getStr())
  let newW = workLEfromBEHex(req["new_tip_work_hex"].getStr())
  if compareWork256(newW, oldW) <= 0:
    # No reorg — view untouched, side branch never evaluated.
    return """{"outcome":"no-reorg-equal-or-less-work","connected_count":0,""" &
           """"fork_utxo_digest":"""" & viewDigest(view) & "\"}"

  # ===== (2) DEPTH CAP (handleReorg MAX_REORG_DEPTH=100) =====
  let discArr = if req.hasKey("disconnect"): req["disconnect"] else: newJArray()
  if discArr.len > chainstate.MAX_REORG_DEPTH:
    return """{"outcome":"reorg-too-deep","reject_reason":"reorg-depth-exceeds-max"}"""

  # ===== (3) DISCONNECT phase — drive REAL chainstate.disconnectBlock =====
  # A throwaway temp RocksDB ChainState seeded with the working coins-view.
  let tmpDir = getTempDir() / ("nimrod-reorg-" & $getCurrentProcessId() & "-" &
                               $epochTime().int64 & "-" & $rand(high(int)))
  createDir(tmpDir)
  var cs = newChainState(tmpDir, params)
  defer:
    cs.close()
    try: removeDir(tmpDir)
    except CatchableError: discard

  # Seed the real UTXO db from the working coins-view.
  for (k, c) in view.pairs:
    cs.db.putUtxo(OutPoint(txid: k[0], vout: k[1]),
                  UtxoEntry(output: TxOut(value: Satoshi(c.value), scriptPubKey: c.spk),
                            height: c.height, isCoinbase: c.isCoinbase))

  var disconnectResult = "ok"
  for d in discArr:
    let blk = deserializeBlock(hexDecode(d["block_hex"].getStr()))
    let height = int32(d["height"].getBiggestInt())
    # Build UndoData from the supplied undo records: per tx_index, restore each
    # vin coin at the spending tx's corresponding prevout.
    var undo = UndoData()
    if d.hasKey("undo"):
      for u in d["undo"]:
        let txIndex = int(u["tx_index"].getBiggestInt())
        if txIndex < 0 or txIndex >= blk.txs.len:
          raise newException(ValueError, "undo tx_index out of range: " & $txIndex)
        let tx = blk.txs[txIndex]
        var vi = 0
        for coinJ in u["vin"]:
          if vi >= tx.inputs.len:
            raise newException(ValueError, "undo vin count exceeds tx inputs")
          let (_, _, c) = coinFromJson(coinJ)
          undo.spentOutputs.add((tx.inputs[vi].prevOut,
            UtxoEntry(output: TxOut(value: Satoshi(c.value), scriptPubKey: c.spk),
                      height: c.height, isCoinbase: c.isCoinbase)))
          inc vi

    var fClean = true
    let dres = cs.disconnectBlock(blk, height, undo, addr fClean)
    if not dres.isOk:
      return """{"outcome":"reorg-rejected","disconnect_result":"failed",""" &
             """"connected_count":0,"reject_reason":"""" &
             jsonEscape(dres.error) & "\"}"
    if not fClean:
      disconnectResult = "unclean"

    # Reflect the disconnect into the shim-threaded view: remove the block's
    # created outputs, restore the undo coins (mirrors the REAL mutation above).
    for txIdx in countdown(blk.txs.len - 1, 0):
      let tx = blk.txs[txIdx]
      let txId = tx.txid()
      for voutIdx in 0 ..< tx.outputs.len:
        if isUnspendable(tx.outputs[voutIdx].scriptPubKey): continue
        view.del((txId, uint32(voutIdx)))
    for (outpoint, entry) in undo.spentOutputs:
      view[(outpoint.txid, outpoint.vout)] = ShimCoin(
        spk: entry.output.scriptPubKey, value: int64(entry.output.value),
        height: entry.height, isCoinbase: entry.isCoinbase)

  # ===== (4) CONNECT phase — REAL validateBlock + verifyScripts per block =====
  # Lookup closure over the shim-threaded (post-disconnect, incrementally
  # advanced) view + intra-block coins of the block under validation.
  let connArr = if req.hasKey("connect"): req["connect"] else: newJArray()
  var connected = 0
  for cb in connArr:
    let blk = deserializeBlock(hexDecode(cb["block_hex"].getStr()))
    let height = int32(cb["height"].getBiggestInt())

    # snapshot the view so the lookup closure is gcsafe/raises:[] over it
    let viewCap = view
    let lookup = proc(op: OutPoint): Option[UtxoEntry] {.gcsafe, raises: [].} =
      let key = (op.txid, op.vout)
      if viewCap.hasKey(key):
        try:
          let c = viewCap[key]
          some(UtxoEntry(output: TxOut(value: Satoshi(c.value), scriptPubKey: c.spk),
                         height: c.height, isCoinbase: c.isCoinbase))
        except KeyError: none(UtxoEntry)
      else:
        none(UtxoEntry)

    let reason = revalidateConnectBlock(blk, height, params, lookup)
    if reason.len > 0:
      return """{"outcome":"reorg-rejected","disconnect_result":"""" &
             disconnectResult & """","connected_count":""" & $connected &
             ""","reject_reason":"""" & jsonEscape(reason) & "\"}"

    # Block accepted: thread its UTXO delta into the view (spend inputs, create
    # outputs) so the NEXT connect block sees the post-connect coins-view
    # (R2 double-spend across blocks resolves here).
    for txIdx, tx in blk.txs:
      let txId = tx.txid()
      if txIdx > 0:
        for input in tx.inputs:
          view.del((input.prevOut.txid, input.prevOut.vout))
      for voutIdx, output in tx.outputs:
        if isUnspendable(output.scriptPubKey): continue
        view[(txId, uint32(voutIdx))] = ShimCoin(
          spk: output.scriptPubKey, value: int64(output.value),
          height: height, isCoinbase: txIdx == 0)
    inc connected

  result = """{"outcome":"reorg-applied","disconnect_result":"""" &
           disconnectResult & """","connected_count":""" & $connected &
           ""","fork_utxo_digest":"""" & viewDigest(view) & "\"}"

## HEADER-LEVEL reject differential op `checkheader`. Drives nimrod's REAL
## header-acceptance gates — the SAME two procs validateBlock's Step 1a/1b call
## (validation.nim:1348-1360) — over an EXPLICIT (header, prev-context) tuple
## with a flag-gated injected clock, so the header reject bar is exercised
## deterministically without a live tip:
##
##   Stage 1  validateBlockHeader(header, prevIndex, params,
##              checkPow = not skip_pow, currentTime = current_time)
##            -> high-hash  (Core CheckBlockHeader -> CheckProofOfWork, which
##                           now folds nBits-malformed / target>powLimit /
##                           hash>target into one verdict via pow.checkProofOfWork)
##            -> time-too-new (Core ContextualCheckBlockHeader:4108, WALL CLOCK;
##                           injected via the new currentTime param — sentinel 0
##                           disables it, exactly the corpus's determinism control)
##            -> prevHash link
##
##   Stage 2  contextualCheckBlockHeaderEx(header, height, prevHeader, prevHash,
##              mtp, params, expectedBitsOverride, firstHeader, firstHeight)
##            -> bad-diffbits  (Gate 1, FIRST: header.bits == GetNextWorkRequired
##                              computed by nimrod's OWN pow.getNextWorkRequired
##                              over the prev (+ optional first) context — NOT the
##                              block's own bits; an explicit expected_bits override
##                              isolates the gate on retarget boundaries)
##            -> time-too-old  (Gate 2: header.ts > mtp)
##            -> time-timewarp-attack (Gate 3: BIP94, testnet4 boundary, ts<prev-600)
##            -> bad-version   (Gate 4: v<2/<3/<4 post BIP34/66/65)
##
## bad-diffbits is THE flagship false-accept guard. nimrod ALREADY enforces it
## (validation.nim:988 header.bits != expectedBits -> veIncorrectProofOfWork),
## so this op confirms there is no hole — it never compares against the block's
## own bits, only the prev-context-derived expected nBits.
##
## bad-version reason: nimrod's bip22String(veBadBlockVersion) is the bare token
## "bad-version"; Core formats `strprintf("bad-version(0x%08x)", block.nVersion)`
## (validation.cpp:4116). Since the shim is the differential driver and HAS the
## header version, it appends the Core `(0x%08x)` suffix here — the same place
## Core does it — so the token matches the corpus byte-for-byte. The DECISION
## (reject) and the gate (version) are nimrod's; only the printf-style suffix is
## reconstructed in the driver.
##
##   request:  {"op":"checkheader","network":"...","header_hex":"<80B>",
##              "height":<int>,
##              "prev":{"bits":"<8hex>","time":<u32>,"hash":"<display-hex>"},
##              "mtp":<u32>,"current_time":<int64; 0 disables time-too-new>,
##              "skip_pow":<bool>,
##              "expected_bits":"<8hex>"?,            # opt diffbits override
##              "first":{"height":<int>,"bits":"<8hex>","time":<u32>}?}  # opt
##   response: {"accept":true} | {"accept":false,"reason":"<bip22 token>"}
##             {"error":"..."}  (cannot evaluate -> driver skips)
proc processCheckHeader(req: JsonNode): string =
  let network = networkFromToken(req["network"].getStr())
  let params = getParams(network)

  let headerBytes = hexDecode(req["header_hex"].getStr())
  if headerBytes.len != 80:
    raise newException(ValueError, "header_hex not 80 bytes: " & $headerBytes.len)
  let header = deserializeBlockHeader(headerBytes)

  let height = int32(req["height"].getBiggestInt())
  let currentTime = if req.hasKey("current_time"): req["current_time"].getBiggestInt()
                    else: 0'i64
  # skip_pow defaults FALSE for checkheader: the point is to drive the strict
  # range-aware pow.checkProofOfWork over a crafted header for the high-hash class.
  let skipPow = if req.hasKey("skip_pow"): req["skip_pow"].getBool() else: false

  let prev = req["prev"]
  let prevBits = parseBits(prev["bits"].getStr())
  let prevTime = uint32(prev["time"].getBiggestInt())
  let mtp = uint32(req["mtp"].getBiggestInt())

  # prevIndex: hash = the header's OWN prevBlock (so validateBlockHeader's
  # prevHash-link gate passes), bits/timestamp = the supplied prev-context.
  var prevHeader = default(BlockHeader)
  prevHeader.bits = prevBits
  prevHeader.timestamp = prevTime
  let prevIndex = chainstate.BlockIndex(
    hash: header.prevBlock,
    height: height - 1,
    header: prevHeader,
    prevHash: default(BlockHash)
  )

  # ---- Stage 1: CheckBlockHeader (high-hash) + time-too-new (injected clock) +
  # prevHash, all via nimrod's REAL validateBlockHeader. minPowChecked=true so the
  # PRESYNC too-little-chainwork gate (not under test) does not fire.
  let hdrRes = validateBlockHeader(header, prevIndex, params,
                                   checkPow = not skipPow,
                                   minPowChecked = true,
                                   currentTime = currentTime)
  if not hdrRes.isOk:
    return """{"accept":false,"reason":"""" &
      jsonEscape(bip22String(hdrRes.error)) & "\"}"

  # ---- Stage 2: ContextualCheckBlockHeader (bad-diffbits / time-too-old /
  # timewarp / bad-version) via the explicit-input twin contextualCheckBlockHeaderEx.
  let expectedOverride =
    if req.hasKey("expected_bits"):
      int64(parseBits(req["expected_bits"].getStr()))
    else:
      -1'i64
  var firstHeader = default(BlockHeader)
  var firstHeight = -1'i32
  if req.hasKey("first") and req["first"].kind == JObject:
    let f = req["first"]
    firstHeader.bits = parseBits(f["bits"].getStr())
    firstHeader.timestamp = uint32(f["time"].getBiggestInt())
    firstHeight = int32(f["height"].getBiggestInt())

  let ctxRes = contextualCheckBlockHeaderEx(
    header, height, prevHeader, header.prevBlock, mtp, params,
    expectedOverride, firstHeader, firstHeight)
  if not ctxRes.isOk:
    # Core formats bad-version with the nVersion suffix (validation.cpp:4116);
    # reconstruct it here (the driver) so the token matches the corpus.
    if ctxRes.error == veBadBlockVersion:
      let v = uint32(header.version)
      return """{"accept":false,"reason":"bad-version(0x""" &
        toLowerAscii(toHex(v, 8)) & ")\"}"
    return """{"accept":false,"reason":"""" &
      jsonEscape(bip22String(ctxRes.error)) & "\"}"

  result = """{"accept":true}"""

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
  of "checkblock": processCheckBlock(req)
  of "checkbip30": processCheckBip30(req)
  of "checkheader": processCheckHeader(req)
  of "reorg": processReorg(req)
  else: raise newException(ValueError, "unknown op: " & op)

proc main() =
  randomize()
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
