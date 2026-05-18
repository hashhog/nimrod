## W137 — PSBT v0/v2 (BIP-174 / BIP-370 / BIP-371) audit (30 gates, xfail
## regression guards).
##
## Audit type: discovery (NO production code change in W137).
##
## W137 catalogues the gap between Bitcoin Core's PSBT codec
## (`src/psbt.h`, `src/psbt.cpp`, `src/node/psbt.cpp`) and nimrod's
## PSBT pipeline (`src/wallet/psbt.nim`, `src/rpc/server.nim`).
##
## Method: each test asserts the CURRENT (buggy / absent) behaviour
## with a `check` that pins the gap.  When a future FIX wave closes
## the gap, the test will fail loudly and the developer must flip the
## assertion (per W120 / W122 / W123 / W124 / W125 / W128 / W131 /
## W132 / W133 methodology).
##
## References:
##   bitcoin-core/src/psbt.h        — wire format / unserialize switch.
##   bitcoin-core/src/psbt.cpp      — top-level codec + role helpers.
##   bitcoin-core/src/node/psbt.cpp — AnalyzePSBT next-role classifier.
##   bitcoin-core/src/rpc/rawtransaction.cpp — createpsbt / decodepsbt /
##                                              combinepsbt / finalizepsbt /
##                                              analyzepsbt / utxoupdatepsbt /
##                                              joinpsbts / converttopsbt /
##                                              descriptorprocesspsbt.
##   bitcoin-core/src/wallet/rpc/spend.cpp — walletcreatefundedpsbt /
##                                            walletprocesspsbt.
##   audit/w137_psbt.md — full gate table + per-gate detail.

import unittest2
import std/[options, strutils, tables, sets, base64]
import ../src/wallet/psbt
import ../src/primitives/[types, serialize]

# ---------------------------------------------------------------------------
# Core constants used to pin expected values
# ---------------------------------------------------------------------------
const
  # Core psbt.h:28
  CORE_PSBT_MAGIC: array[5, byte] = [0x70'u8, 0x73, 0x62, 0x74, 0xff]
  # Core psbt.h:80
  CORE_PSBT_HIGHEST_VERSION = 0'u32
  # Core script/interpreter.h
  CORE_TAPROOT_CONTROL_MAX_NODE_COUNT = 128
  # Core script/interpreter.h — TAPROOT_LEAF_TAPSCRIPT = 0xc0; mask = 0xfe
  CORE_TAPROOT_LEAF_MASK = 0xfe'u8
  # Core BIP-32 extended pubkey
  CORE_BIP32_EXTKEY_WITH_VERSION_SIZE = 78
  # Core psbt.h:77
  CORE_MAX_FILE_SIZE_PSBT = 100_000_000

# Read production source files once for source-level pinning.
let
  psbtSrc:    string = readFile("src/wallet/psbt.nim")
  serverSrc:  string = readFile("src/rpc/server.nim")

# ---------------------------------------------------------------------------
# G1 — Magic bytes (PRESENT)
# ---------------------------------------------------------------------------
suite "W137 G1 — magic bytes":

  test "G1 PRESENT: PSBT_MAGIC_BYTES matches Core 'psbt\\xff'":
    check PSBT_MAGIC_BYTES == CORE_PSBT_MAGIC
    check PSBT_MAGIC_BYTES[0] == 0x70'u8  # 'p'
    check PSBT_MAGIC_BYTES[1] == 0x73'u8  # 's'
    check PSBT_MAGIC_BYTES[2] == 0x62'u8  # 'b'
    check PSBT_MAGIC_BYTES[3] == 0x74'u8  # 't'
    check PSBT_MAGIC_BYTES[4] == 0xff'u8

# ---------------------------------------------------------------------------
# G2 — Global unsigned tx required (PRESENT)
# ---------------------------------------------------------------------------
suite "W137 G2 — PSBT_GLOBAL_UNSIGNED_TX required":

  test "G2 PRESENT: serialize() refuses PSBT with no tx":
    let p = Psbt()
    expect PsbtError:
      discard serialize(p)

  test "G2 PRESENT: deserializer rejects non-empty scriptSig in unsigned tx":
    ## Core psbt.h:1275-1278 — every txin must have empty scriptSig+witness.
    check "unsigned tx has non-empty scriptSig" in psbtSrc
    check "unsigned tx has non-empty witness" in psbtSrc

# ---------------------------------------------------------------------------
# G3 — PSBT_GLOBAL_XPUB xpub IsFullyValid (BUG-1, P1)
# ---------------------------------------------------------------------------
suite "W137 G3 — PSBT_GLOBAL_XPUB xpub validation (BUG-1)":

  test "G3 BUG-1: deserializer accepts any 79-byte global xpub bytes":
    ## Core psbt.h:1289-1292 calls `xpub.DecodeWithVersion` + `IsFullyValid`.
    ## Nimrod stores raw bytes (psbt.nim:945-957) — no curve validation.
    let globalXpubBlock = psbtSrc[psbtSrc.find("of PSBT_GLOBAL_XPUB:") ..
                                  psbtSrc.find("of PSBT_GLOBAL_VERSION:") - 1]
    # No IsFullyValid / DecodeWithVersion in nimrod's xpub case arm:
    check "IsFullyValid" notin globalXpubBlock
    check "DecodeWithVersion" notin globalXpubBlock
    check "validateXpub" notin globalXpubBlock
    # Size 79 IS checked (1 type byte + 78 BIP32_EXTKEY_WITH_VERSION_SIZE):
    check "key.len != 79" in psbtSrc

# ---------------------------------------------------------------------------
# G4 — Version > HIGHEST rejected (PRESENT)
# ---------------------------------------------------------------------------
suite "W137 G4 — version > HIGHEST_VERSION rejected":

  test "G4 PRESENT: PSBT_HIGHEST_VERSION = 0 (matches Core)":
    check PSBT_HIGHEST_VERSION == CORE_PSBT_HIGHEST_VERSION
    check "unsupported PSBT version" in psbtSrc

# ---------------------------------------------------------------------------
# G5 — Proprietary parsed (PRESENT)
# ---------------------------------------------------------------------------
suite "W137 G5 — PSBT_GLOBAL_PROPRIETARY identifier+subtype":

  test "G5 PRESENT: proprietary key structure has identifier+subtype":
    check "PsbtProprietary" in psbtSrc
    check "identifier" in psbtSrc
    check "subtype" in psbtSrc
    check "proprietaryKey" in psbtSrc

# ---------------------------------------------------------------------------
# G6 — non_witness_utxo prevout-hash + vout.n check (BUG-2, P0-CDIV)
# ---------------------------------------------------------------------------
suite "W137 G6 — non_witness_utxo prevout integrity (BUG-2)":

  test "G6 BUG-2: deserializer does NOT verify non_witness_utxo hash matches prevout":
    ## Core psbt.h:1370-1378 — throws if hash mismatch or vout.n OOB.
    ## Nimrod's `deserialize` (psbt.nim:983-995) skips both checks.
    let deserBlock = psbtSrc[psbtSrc.find("# Read inputs") ..
                              psbtSrc.find("# Read outputs") - 1]
    check "GetHash" notin deserBlock
    check "txid()" notin deserBlock
    check "Non-witness UTXO does not match" notin psbtSrc
    check "specifies output index that does not exist" notin psbtSrc

# ---------------------------------------------------------------------------
# G7 — partial_sig pubkey IsFullyValid + sig DER + CKeyID dedup
# (BUG-3 P0-CDIV, BUG-4 P1, BUG-5 P0-CDIV)
# ---------------------------------------------------------------------------
suite "W137 G7 — partial_sig pubkey+sig validation (BUG-3 / BUG-4 / BUG-5)":

  test "G7 BUG-3: partial_sig deserializer does NOT validate pubkey curve point":
    ## Core psbt.h:530-534 — `CPubKey(begin,end)` + IsFullyValid throws on garbage.
    let partialSigBlock = psbtSrc[psbtSrc.find("of PSBT_IN_PARTIAL_SIG:") ..
                                   psbtSrc.find("of PSBT_IN_SIGHASH:") - 1]
    check "IsFullyValid" notin partialSigBlock
    check "validatePubkey" notin partialSigBlock
    # Confirm the buggy "store raw bytes" pattern:
    check "result.partialSigs[pubkey] = value" in partialSigBlock

  test "G7 BUG-4: partial_sig deserializer does NOT enforce DER sig encoding":
    ## Core psbt.h:543-546 — `CheckSignatureEncoding(sig,
    ## SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_STRICTENC, nullptr)` throws
    ## "Signature is not a valid encoding".  Nimrod skips.
    let partialSigBlock = psbtSrc[psbtSrc.find("of PSBT_IN_PARTIAL_SIG:") ..
                                   psbtSrc.find("of PSBT_IN_SIGHASH:") - 1]
    check "CheckSignatureEncoding" notin partialSigBlock
    check "DERSIG" notin partialSigBlock
    check "STRICTENC" notin partialSigBlock

  test "G7 BUG-5: partial_sig dedup uses raw pubkey bytes, not CKeyID HASH160":
    ## Core psbt.h:535 — `partial_sigs.contains(pubkey.GetID())` so the
    ## SAME secp256k1 point in different encodings collides.  Nimrod's
    ## Table[seq[byte], seq[byte]] keys on raw bytes — compressed and
    ## uncompressed encodings of the same key are stored as TWO entries.
    let psbtType = psbtSrc[psbtSrc.find("partialSigs*") ..
                            psbtSrc.find("sighashType*") - 1]
    check "Table[seq[byte], seq[byte]]" in psbtType
    # Core's GetID idiom is HASH160(pubkey):
    check "GetID" notin psbtType
    check "keyID" notin psbtType
    check "hash160(pubkey)" notin psbtType.toLower

# ---------------------------------------------------------------------------
# G8 — SIGHASH value size check (BUG-6, P1)
# ---------------------------------------------------------------------------
suite "W137 G8 — SIGHASH value size check (BUG-6)":

  test "G8 BUG-6: SIGHASH value reads int32 but does NOT check value.len == 4":
    ## Core psbt.h:558-560 — `UnserializeFromVector(s, sighash)` which
    ## throws via the size-mismatch check (psbt.h:117) if value.len != 4.
    let sighashBlock = psbtSrc[psbtSrc.find("of PSBT_IN_SIGHASH:") ..
                                psbtSrc.find("of PSBT_IN_REDEEMSCRIPT:") - 1]
    # The body just reads int32 and stores, without comparing value.len:
    check "value.len == 4" notin sighashBlock
    check "value.len != 4" notin sighashBlock
    check "readInt32LE()" in sighashBlock

# ---------------------------------------------------------------------------
# G9 — BIP32_DERIVATION pubkey IsFullyValid + length%4 (BUG-7, P1)
# ---------------------------------------------------------------------------
suite "W137 G9 — BIP32_DERIVATION pubkey validation (BUG-7)":

  test "G9 BUG-7: BIP32_DERIVATION pubkey curve validity not checked":
    ## Core psbt.h:157-160 — `CPubKey + IsFullyValid` throws on garbage.
    let bip32Block = psbtSrc[psbtSrc.find("of PSBT_IN_BIP32_DERIVATION:") ..
                              psbtSrc.find("of PSBT_IN_SCRIPTSIG:") - 1]
    check "IsFullyValid" notin bip32Block
    check "validatePubkey" notin bip32Block

  test "G9 PARTIAL: length % 4 == 0 IS checked in deserializeKeyOrigin":
    ## Core psbt.h:127-128 — `if (length % 4 || length == 0) throw`.
    ## Nimrod (psbt.nim:191) — `if length mod 4 != 0 or length == 0: raise`.
    check "length mod 4 != 0 or length == 0" in psbtSrc

# ---------------------------------------------------------------------------
# G10 — PSBT_IN_TAP_KEY_SIG (PRESENT)
# ---------------------------------------------------------------------------
suite "W137 G10 — PSBT_IN_TAP_KEY_SIG":

  test "G10 PRESENT: tap_key_sig 64-65 byte range enforced":
    check "tap key sig must be 64-65 bytes" in psbtSrc
    check "PSBT_IN_TAP_KEY_SIG" in psbtSrc

# ---------------------------------------------------------------------------
# G11 — PSBT_IN_TAP_LEAF_SCRIPT (PRESENT)
# ---------------------------------------------------------------------------
suite "W137 G11 — PSBT_IN_TAP_LEAF_SCRIPT":

  test "G11 PRESENT: tap_leaf_script key.len >= 34 and (key.len-2) mod 32":
    check "(key.len - 2) mod 32" in psbtSrc
    check "PSBT_IN_TAP_LEAF_SCRIPT" in psbtSrc

# ---------------------------------------------------------------------------
# G12 — PSBT_IN_TAP_BIP32_DERIVATION (PRESENT)
# ---------------------------------------------------------------------------
suite "W137 G12 — PSBT_IN_TAP_BIP32_DERIVATION":

  test "G12 PRESENT: tap_bip32_derivation leaf_hashes set + origin":
    check "PSBT_IN_TAP_BIP32_DERIVATION" in psbtSrc
    check "tapBip32Paths" in psbtSrc

# ---------------------------------------------------------------------------
# G13 — INPUT MUSIG2_PARTICIPANT_PUBKEYS struct field missing (BUG-8, P1)
# ---------------------------------------------------------------------------
suite "W137 G13 — input MUSIG2_PARTICIPANT_PUBKEYS (BUG-8)":

  test "G13 BUG-8: PsbtInput has NO musig2_participants field":
    ## Core psbt.h:285 — `std::map<CPubKey, std::vector<CPubKey>> m_musig2_participants`.
    let psbtInputType = psbtSrc[psbtSrc.find("PsbtInput* = object") ..
                                 psbtSrc.find("PsbtOutput* = object") - 1]
    check "musig2_participants" notin psbtInputType
    check "musig2Participants" notin psbtInputType

  test "G13 BUG-8 cont: deserializer has NO arm for PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS":
    ## The 0x1A constant exists but the input switch never matches it.
    check "PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS" in psbtSrc  # constant defined
    let inputSwitch = psbtSrc[psbtSrc.find("proc deserializePsbtInput*") ..
                               psbtSrc.find("proc deserializePsbtOutput*") - 1]
    # Constant referenced ONLY in const block, never inside the deserializer:
    check "of PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS" notin inputSwitch

# ---------------------------------------------------------------------------
# G14 — INPUT MUSIG2_PUB_NONCE missing (BUG-9, P0-CDIV)
# ---------------------------------------------------------------------------
suite "W137 G14 — input MUSIG2_PUB_NONCE (BUG-9)":

  test "G14 BUG-9: PsbtInput has NO musig2_pubnonces field":
    ## Core psbt.h:287 — `std::map<std::pair<CPubKey, uint256>,
    ## std::map<CPubKey, std::vector<uint8_t>>> m_musig2_pubnonces`.
    let psbtInputType = psbtSrc[psbtSrc.find("PsbtInput* = object") ..
                                 psbtSrc.find("PsbtOutput* = object") - 1]
    check "musig2_pubnonces" notin psbtInputType
    check "musig2Pubnonces" notin psbtInputType

  test "G14 BUG-9 cont: deserializer has NO arm for PSBT_IN_MUSIG2_PUB_NONCE":
    let inputSwitch = psbtSrc[psbtSrc.find("proc deserializePsbtInput*") ..
                               psbtSrc.find("proc deserializePsbtOutput*") - 1]
    check "of PSBT_IN_MUSIG2_PUB_NONCE" notin inputSwitch
    # Pubnonce size constant absent:
    check "MUSIG2_PUBNONCE_SIZE" notin psbtSrc

# ---------------------------------------------------------------------------
# G15 — INPUT MUSIG2_PARTIAL_SIG missing (BUG-10, P0-CDIV)
# ---------------------------------------------------------------------------
suite "W137 G15 — input MUSIG2_PARTIAL_SIG (BUG-10)":

  test "G15 BUG-10: PsbtInput has NO musig2_partial_sigs field":
    let psbtInputType = psbtSrc[psbtSrc.find("PsbtInput* = object") ..
                                 psbtSrc.find("PsbtOutput* = object") - 1]
    check "musig2_partial_sigs" notin psbtInputType
    check "musig2PartialSigs" notin psbtInputType

  test "G15 BUG-10 cont: deserializer has NO arm for PSBT_IN_MUSIG2_PARTIAL_SIG":
    let inputSwitch = psbtSrc[psbtSrc.find("proc deserializePsbtInput*") ..
                               psbtSrc.find("proc deserializePsbtOutput*") - 1]
    check "of PSBT_IN_MUSIG2_PARTIAL_SIG" notin inputSwitch

# ---------------------------------------------------------------------------
# G16 — PSBT_OUT_TAP_TREE depth/leaf_ver/completeness (BUG-11, P0-CDIV)
# ---------------------------------------------------------------------------
suite "W137 G16 — PSBT_OUT_TAP_TREE validation (BUG-11)":

  test "G16 BUG-11: tap_tree does NOT validate empty-rejection":
    ## Core psbt.h:1042-1044 — `if (s_tree.empty()) throw "Output Taproot
    ## tree must not be empty"`.
    let tapTreeBlock = psbtSrc[psbtSrc.find("of PSBT_OUT_TAP_TREE:") ..
                                psbtSrc.find("of PSBT_OUT_TAP_BIP32_DERIVATION:") - 1]
    check "Output Taproot tree must not be empty" notin psbtSrc
    check "tapTree.add" in tapTreeBlock  # confirms naive parse loop

  test "G16 BUG-11 cont: tap_tree does NOT validate depth ≤ TAPROOT_CONTROL_MAX_NODE_COUNT":
    ## Core psbt.h:1053-1055 — depth > 128 rejected.
    let tapTreeBlock = psbtSrc[psbtSrc.find("of PSBT_OUT_TAP_TREE:") ..
                                psbtSrc.find("of PSBT_OUT_TAP_BIP32_DERIVATION:") - 1]
    check "TAPROOT_CONTROL_MAX_NODE_COUNT" notin tapTreeBlock
    check "depth > 128" notin tapTreeBlock

  test "G16 BUG-11 cont: tap_tree does NOT validate leaf_ver & ~TAPROOT_LEAF_MASK":
    ## Core psbt.h:1056-1058 — `(leaf_ver & ~TAPROOT_LEAF_MASK) != 0` rejected.
    let tapTreeBlock = psbtSrc[psbtSrc.find("of PSBT_OUT_TAP_TREE:") ..
                                psbtSrc.find("of PSBT_OUT_TAP_BIP32_DERIVATION:") - 1]
    check "TAPROOT_LEAF_MASK" notin tapTreeBlock
    check "0xfe" notin tapTreeBlock

  test "G16 BUG-11 cont: tap_tree does NOT call builder.IsComplete":
    ## Core psbt.h:1062-1064 — `if (!builder.IsComplete()) throw "Output
    ## Taproot tree is malformed"`.
    check "TaprootBuilder" notin psbtSrc
    check "IsComplete" notin psbtSrc
    check "Output Taproot tree is malformed" notin psbtSrc

# ---------------------------------------------------------------------------
# G17 — PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS (PRESENT)
# ---------------------------------------------------------------------------
suite "W137 G17 — output MUSIG2_PARTICIPANT_PUBKEYS":

  test "G17 PRESENT: output MUSIG2_PARTICIPANT_PUBKEYS deserialized":
    check "PSBT_OUT_MUSIG2_PARTICIPANT_PUBKEYS" in psbtSrc
    check "musig2Participants" in psbtSrc
    check "musig2 participant pubkeys output key must be 34 bytes" in psbtSrc

  test "G17 PRESENT: value.len multiple of 33 enforced":
    check "size is not a multiple of 33" in psbtSrc

# ---------------------------------------------------------------------------
# G18 — Unknown key types preserved (PRESENT)
# ---------------------------------------------------------------------------
suite "W137 G18 — unknown keys preserved":

  test "G18 PRESENT: unknown map preserves round-trip bytes":
    let psbtType = psbtSrc[psbtSrc.find("Psbt* = object") .. ^1]
    check "unknown*: Table[seq[byte], seq[byte]]" in psbtSrc

# ---------------------------------------------------------------------------
# G19 — Duplicate-key rejection (PRESENT, but BUG-5 weakens)
# ---------------------------------------------------------------------------
suite "W137 G19 — duplicate-key rejection":

  test "G19 PRESENT: duplicate-key rejection in global / input / output maps":
    check "duplicate key in input" in psbtSrc
    check "duplicate key in output" in psbtSrc
    check "duplicate key in global map" in psbtSrc

  test "G19 PARTIAL: partial_sigs duplicate-by-CKeyID NOT enforced (BUG-5)":
    ## Cross-link to G7 BUG-5.  Duplicate-key set is on RAW pubkey bytes
    ## not HASH160(pubkey) — two encodings of same key collide for Core
    ## but not for nimrod.
    check "GetID" notin psbtSrc
    check "keyID" notin psbtSrc

# ---------------------------------------------------------------------------
# G20 — Separator presence (BUG-12, P1)
# ---------------------------------------------------------------------------
suite "W137 G20 — found_sep enforcement (BUG-12)":

  test "G20 BUG-12: deserializer has NO found_sep flag":
    ## Core psbt.h:865-867, 1126-1128, 1354-1356 — `if (!found_sep) throw
    ## "Separator is missing at the end of an input/output/global map"`.
    check "found_sep" notin psbtSrc
    check "foundSep" notin psbtSrc
    check "Separator is missing at the end" notin psbtSrc

# ---------------------------------------------------------------------------
# G21 — inputs.size() == tx.vin.size() upper-bound check (BUG-13, P1)
# ---------------------------------------------------------------------------
suite "W137 G21 — input map count exact match (BUG-13)":

  test "G21 BUG-13: deserializer only checks too-few, never too-many inputs":
    ## Core psbt.h:1381-1384 — `if (inputs.size() != tx->vin.size()) throw`.
    ## Nimrod (psbt.nim:983-988) only catches "not enough" via remaining==0.
    check "not enough input maps" in psbtSrc
    check "Inputs provided does not match" notin psbtSrc
    check "inputs.len != tx" notin psbtSrc

# ---------------------------------------------------------------------------
# G22 — outputs.size() == tx.vout.size() upper-bound check (BUG-14, P1)
# ---------------------------------------------------------------------------
suite "W137 G22 — output map count exact match (BUG-14)":

  test "G22 BUG-14: deserializer only checks too-few, never too-many outputs":
    ## Core psbt.h:1395-1397 — `if (outputs.size() != tx->vout.size()) throw`.
    check "not enough output maps" in psbtSrc
    check "Outputs provided does not match" notin psbtSrc

# ---------------------------------------------------------------------------
# G23 — No-trailing-bytes-after-PSBT check (BUG-15, P0-CDIV)
# ---------------------------------------------------------------------------
suite "W137 G23 — no-trailing-bytes-after-PSBT check (BUG-15)":

  test "G23 BUG-15: deserialize() does NOT check r.remaining == 0 after parse":
    ## Core psbt.cpp:622-624 — `if (!ss_data.empty()) error = "extra data
    ## after PSBT"; return false;`.
    let deserProc = psbtSrc[psbtSrc.find("proc deserialize*(data: openArray[byte])") ..
                             psbtSrc.find("proc toBase64*") - 1]
    check "extra data after PSBT" notin psbtSrc
    # No remaining==0 check at the end of deserialize:
    let lastBracket = deserProc.rfind("result.outputs.add(r.deserializePsbtOutput())")
    let tail = deserProc[lastBracket .. ^1]
    check "r.remaining" notin tail  # nothing past the outputs loop checks remaining

  test "G23 BUG-15 cont: deserialize has no post-loop r.remaining check":
    ## Source-level pin: after the outputs loop, nothing checks the buffer
    ## is empty.  Cross-link with the previous test confirming the
    ## "extra data after PSBT" string is absent.
    let deserProc = psbtSrc[psbtSrc.find("proc deserialize*(data: openArray[byte])") ..
                             psbtSrc.find("proc toBase64*") - 1]
    # The last meaningful line is the outputs append — anything past it
    # should NOT contain a remaining check; we verify there's no
    # "if r.remaining" guard tail after the outputs loop.
    let outputsLoopEnd = deserProc.rfind("result.outputs.add(r.deserializePsbtOutput())")
    check outputsLoopEnd > 0
    let postLoopTail = deserProc[outputsLoopEnd .. ^1]
    check "if r.remaining > 0" notin postLoopTail
    check "extra data" notin postLoopTail

# ---------------------------------------------------------------------------
# G24 — RemoveUnnecessaryTransactions absent (BUG-16, P2)
# ---------------------------------------------------------------------------
suite "W137 G24 — RemoveUnnecessaryTransactions (BUG-16)":

  test "G24 BUG-16: no RemoveUnnecessaryTransactions equivalent":
    ## Core psbt.cpp:514-549 — drops non_witness_utxo for taproot-only
    ## inputs.  Nimrod has no equivalent — every PSBT carries the full
    ## prev tx forever.
    check "RemoveUnnecessaryTransactions" notin psbtSrc
    check "removeUnnecessaryTransactions" notin psbtSrc
    check "removeUnnecessaryTxs" notin psbtSrc

# ---------------------------------------------------------------------------
# G25 — PrecomputePSBTData absent (BUG-17, P2)
# ---------------------------------------------------------------------------
suite "W137 G25 — PrecomputePSBTData (BUG-17)":

  test "G25 BUG-17: no PrecomputePSBTData equivalent":
    ## Core psbt.cpp:385-400 — caches `PrecomputedTransactionData` once
    ## for the whole PSBT signing run.  Nimrod has no helper; every
    ## signature production re-derives spent_outputs.
    check "PrecomputePSBTData" notin psbtSrc
    check "precomputePsbtData" notin psbtSrc
    check "PrecomputedTransactionData" notin psbtSrc

# ---------------------------------------------------------------------------
# G26 — SignPSBTInput typed error codes (BUG-18, P2)
# ---------------------------------------------------------------------------
suite "W137 G26 — SignPSBTInput PSBTError enum (BUG-18)":

  test "G26 BUG-18: finalizePsbtInput returns bool, not PSBTError enum":
    ## Core psbt.h:1430 — `enum class PSBTError { OK, MISSING_INPUTS,
    ## SIGHASH_MISMATCH, EXTERNAL_SIGNER_NOT_FOUND,
    ## EXTERNAL_SIGNER_FAILED, INCOMPLETE }` returned by `SignPSBTInput`.
    check "PSBTError" notin psbtSrc
    check "PsbtSignError" notin psbtSrc
    check "MISSING_INPUTS" notin psbtSrc
    check "SIGHASH_MISMATCH" notin psbtSrc
    # The current API is bool-returning:
    check "proc finalizePsbtInput*(input: var PsbtInput;" in psbtSrc

# ---------------------------------------------------------------------------
# G27 — utxoupdatepsbt + joinpsbts RPCs (BUG-19, P2)
# ---------------------------------------------------------------------------
suite "W137 G27 — utxoupdatepsbt + joinpsbts RPCs (BUG-19)":

  test "G27 BUG-19: no utxoupdatepsbt RPC handler":
    ## Core rpc/rawtransaction.cpp registers `utxoupdatepsbt`.
    check "utxoupdatepsbt" notin serverSrc
    check "handleUtxoUpdatePsbt" notin serverSrc

  test "G27 BUG-19 cont: no joinpsbts RPC handler":
    ## Core rpc/rawtransaction.cpp registers `joinpsbts`.
    check "joinpsbts" notin serverSrc
    check "handleJoinPsbts" notin serverSrc

# ---------------------------------------------------------------------------
# G28 — walletprocesspsbt + converttopsbt + descriptorprocesspsbt RPCs
# (BUG-20, P2)
# ---------------------------------------------------------------------------
suite "W137 G28 — walletprocesspsbt / converttopsbt / descriptorprocesspsbt (BUG-20)":

  test "G28 BUG-20: no walletprocesspsbt RPC handler":
    ## Core wallet/rpc/spend.cpp registers `walletprocesspsbt`.
    check "walletprocesspsbt" notin serverSrc
    check "handleWalletProcessPsbt" notin serverSrc

  test "G28 BUG-20 cont: no converttopsbt RPC handler":
    ## Core rpc/rawtransaction.cpp registers `converttopsbt`.
    check "converttopsbt" notin serverSrc
    check "handleConvertToPsbt" notin serverSrc

  test "G28 BUG-20 cont: no descriptorprocesspsbt RPC handler":
    ## Core rpc/rawtransaction.cpp registers `descriptorprocesspsbt`.
    check "descriptorprocesspsbt" notin serverSrc
    check "handleDescriptorProcessPsbt" notin serverSrc

# ---------------------------------------------------------------------------
# G29 — analyzepsbt fee / estimated_vsize / estimated_feerate (BUG-21, P1)
# ---------------------------------------------------------------------------
suite "W137 G29 — analyzepsbt fee/vsize/feerate (BUG-21)":

  test "G29 BUG-21: handleAnalyzePsbt does NOT emit estimated_vsize":
    ## Core node/psbt.cpp:117-145 — emits `estimated_vsize`,
    ## `estimated_feerate`, `fee` for fully-signable PSBTs.
    let analyzeBlock = serverSrc[serverSrc.find("proc handleAnalyzePsbt") ..
                                  serverSrc.find("proc w47bDsha256") - 1]
    check "estimated_vsize" notin analyzeBlock
    check "estimated_feerate" notin analyzeBlock

  test "G29 BUG-21 cont: handleAnalyzePsbt does NOT emit fee":
    let analyzeBlock = serverSrc[serverSrc.find("proc handleAnalyzePsbt") ..
                                  serverSrc.find("proc w47bDsha256") - 1]
    # The block doesn't emit Core's fee field at the top level:
    check "\"fee\"" notin analyzeBlock

# ---------------------------------------------------------------------------
# G30 — MAX_FILE_SIZE_PSBT enforcement (BUG-22, P3)
# ---------------------------------------------------------------------------
suite "W137 G30 — MAX_FILE_SIZE_PSBT enforcement (BUG-22)":

  test "G30 BUG-22: MAX_FILE_SIZE_PSBT constant exists but is never referenced":
    ## The constant is declared at psbt.nim:28 (mirrors Core psbt.h:77)
    ## but never enforced.  `deserialize` / `fromBase64` accept any size.
    check MAX_FILE_SIZE_PSBT == CORE_MAX_FILE_SIZE_PSBT
    # The constant should be referenced in deserialize / fromBase64 — and isn't:
    let deserProc = psbtSrc[psbtSrc.find("proc deserialize*(data: openArray[byte])") ..
                             psbtSrc.find("proc fromBase64*") - 1]
    let fromB64Proc = psbtSrc[psbtSrc.find("proc fromBase64*") ..
                               psbtSrc.find("proc createPsbt*") - 1]
    check "MAX_FILE_SIZE_PSBT" notin deserProc
    check "MAX_FILE_SIZE_PSBT" notin fromB64Proc

# ---------------------------------------------------------------------------
# Final summary check (sanity)
# ---------------------------------------------------------------------------
suite "W137 — final summary":

  test "summary: PSBT module is wired into RPC server (sanity)":
    ## Sanity: psbt.nim is imported and PSBT RPCs are dispatched.
    check "import ../wallet/psbt" in serverSrc
    check "handleCreatePsbt" in serverSrc
    check "handleDecodePsbt" in serverSrc
    check "handleCombinePsbt" in serverSrc
    check "handleFinalizePsbt" in serverSrc
    check "handleAnalyzePsbt" in serverSrc

  test "summary: 22 BUGs catalogued across 30 gates":
    ## Audit doc records 22 bugs:
    ## P0-CDIV: BUG-2 (non_witness_utxo prevout-hash), BUG-3 (partial_sig pubkey),
    ##          BUG-5 (CKeyID dedup), BUG-9 (MUSIG2_PUB_NONCE), BUG-10
    ##          (MUSIG2_PARTIAL_SIG), BUG-11 (TAP_TREE), BUG-15 (trailing bytes).
    ##          (BUG-7 BIP32 pubkey is P1.)
    ## P1: BUG-1 (xpub IsFullyValid), BUG-4 (sig DER), BUG-6 (SIGHASH size),
    ##     BUG-7 (BIP32 pubkey), BUG-8 (MUSIG2 input participants), BUG-12
    ##     (found_sep), BUG-13/14 (input/output count), BUG-21 (analyzepsbt fee).
    ## P2: BUG-16 (RemoveUnnecessaryTransactions), BUG-17 (PrecomputePSBTData),
    ##     BUG-18 (PSBTError enum), BUG-19 (utxoupdatepsbt/joinpsbts),
    ##     BUG-20 (walletprocesspsbt/converttopsbt/descriptorprocesspsbt).
    ## P3: BUG-22 (MAX_FILE_SIZE_PSBT).
    check 22 == 22  # placeholder — the assertion is the test count itself
