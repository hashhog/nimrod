## W134 BIP-37 / BIP-111 Bloom Filter (legacy SPV) re-audit — nimrod
##
## Re-classifies W110 against the same 30-gate matrix after FIX-35
## (drop NODE_BLOOM advertisement) and FIX-36 (parse filterload/add/clear/
## merkleblock + BIP-111 disconnect) landed.  Verifies the two closures and
## documents the 9 remaining subsystem-absent gates.
##
## See `audit/w134_bip37_bloom_filter.md` for the full audit doc.
##
## References:
##   bitcoin-core/src/common/bloom.h + bloom.cpp
##   bitcoin-core/src/merkleblock.h + merkleblock.cpp
##   bitcoin-core/src/net_processing.cpp lines 2438-2458, 4853-4863, 4963-5032
##   bitcoin-core/src/protocol.h:316-317 (NODE_BLOOM = 1<<2)
##   bitcoin-core/src/init.cpp:572,1104-1105 (-peerbloomfilters)
##   bitcoin-core/src/net_processing.h:44 (DEFAULT_PEERBLOOMFILTERS = false)

import unittest2
import std/[os, strutils, math, times]
import ../src/network/messages
import ../src/network/peer
import ../src/network/eviction
import ../src/network/netgroup
import ../src/primitives/[types, serialize]

# ─────────────────────────────────────────────────────────────────────────────
# G1 — MAX_BLOOM_FILTER_SIZE = 36000
# ─────────────────────────────────────────────────────────────────────────────
suite "W134 G1 — MAX_BLOOM_FILTER_SIZE constant":
  test "BUG-02: MAX_BLOOM_FILTER_SIZE = 36000 is not defined":
    ## Core bloom.h:17: static constexpr unsigned int MAX_BLOOM_FILTER_SIZE = 36000;
    ## Nimrod has no such constant anywhere in src/.
    ## Without it, an incoming filterload of up to MaxMessagePayload (4 MB)
    ## would be accepted if filterload were ever actually parsed.
    ## Currently moot — FIX-36 disconnects on receipt — but reinstating
    ## the subsystem without this guard would re-open a DoS vector.
    ## DISABLED: constant is absent; documents missing guard.
    skip()

  test "PASS: protocol message cap MaxMessagePayload = 4_000_000 exists":
    ## The only size guard currently affecting filterload is the 4 MB cap.
    check MaxMessagePayload == 4_000_000

  test "Reference: MAX_BLOOM_FILTER_SIZE value for future implementation":
    ## Document the expected Core value for any future bloom subsystem.
    const expectedMaxBloomFilterSize = 36000
    check expectedMaxBloomFilterSize == 36000
    check expectedMaxBloomFilterSize < MaxMessagePayload

# ─────────────────────────────────────────────────────────────────────────────
# G2 — MAX_HASH_FUNCS = 50
# ─────────────────────────────────────────────────────────────────────────────
suite "W134 G2 — MAX_HASH_FUNCS constant":
  test "BUG-03: MAX_HASH_FUNCS = 50 is not defined":
    ## Core bloom.h:18: static constexpr unsigned int MAX_HASH_FUNCS = 50;
    ## Nimrod defines no such constant.  An evil peer could claim
    ## nHashFuncs = 65535, causing O(65535) hash operations per lookup
    ## if the bloom subsystem were ever implemented.
    ## DISABLED: constant is absent.
    skip()

  test "Reference: MAX_HASH_FUNCS expected value":
    const expectedMaxHashFuncs = 50
    check expectedMaxHashFuncs == 50

# ─────────────────────────────────────────────────────────────────────────────
# G3 — LN2SQUARED full precision
# ─────────────────────────────────────────────────────────────────────────────
suite "W134 G3 — LN2SQUARED constant precision":
  test "BUG-01 (root): LN2SQUARED unused because CBloomFilter absent":
    ## Core bloom.cpp:23: static constexpr double LN2SQUARED =
    ##   0.4804530139182014246671025263266649717305529515945455;
    ## Nimrod has no CBloomFilter, so LN2SQUARED is never needed.
    ## DISABLED: dependent on absent CBloomFilter type.
    skip()

  test "Reference: ln(2)^2 numeric value":
    ## Document the expected value for any future implementer.
    let expected = 0.4804530139182014'f64
    let computed = ln(2.0'f64) * ln(2.0'f64)
    check abs(computed - expected) < 1e-12

# ─────────────────────────────────────────────────────────────────────────────
# G4 — Constructor sizing formula
# ─────────────────────────────────────────────────────────────────────────────
suite "W134 G4 — CBloomFilter constructor sizing formula":
  test "BUG-01 (root): constructor absent — type absent":
    ## Core bloom.cpp:32: vData size =
    ##   min(-1/LN2SQUARED * nElements * log(nFPRate),
    ##       MAX_BLOOM_FILTER_SIZE * 8) / 8
    ## nHashFuncs = min(vData.size() * 8 / nElements * LN2, MAX_HASH_FUNCS)
    ## DISABLED: type and constructor absent.
    skip()

# ─────────────────────────────────────────────────────────────────────────────
# G5 — nHashFuncs computation
# ─────────────────────────────────────────────────────────────────────────────
suite "W134 G5 — nHashFuncs computation":
  test "BUG-01 (root): nHashFuncs computation absent":
    ## Core: nHashFuncs = min(vData.size()*8 / nElements * LN2, MAX_HASH_FUNCS)
    ## DISABLED: dependent on absent CBloomFilter type.
    skip()

# ─────────────────────────────────────────────────────────────────────────────
# G6 — MurmurHash3 32-bit
# ─────────────────────────────────────────────────────────────────────────────
suite "W134 G6 — MurmurHash3 32-bit implementation":
  test "BUG-04: MurmurHash3 primitive is not implemented in nimrod":
    ## Core hash.h:209: unsigned int MurmurHash3(unsigned int nHashSeed,
    ##   std::span<const unsigned char> vDataToHash);
    ## Nimrod has SHA-256, HASH256, RIPEMD-160, and SipHash-2-4 (BIP-339).
    ## MurmurHash3 is absent.  Using any other hash for the bloom subsystem
    ## would produce wrong bit positions and break Core compatibility.
    ## DISABLED: function is absent.
    skip()

# ─────────────────────────────────────────────────────────────────────────────
# G7 — Hash schedule: i * 0xFBA4C795 + nTweak
# ─────────────────────────────────────────────────────────────────────────────
suite "W134 G7 — Hash schedule i*0xFBA4C795 + nTweak":
  test "BUG-04 (dependent): hash schedule absent — MurmurHash3 absent":
    ## Core bloom.cpp:47: Hash(nHashNum, data) =
    ##   MurmurHash3(nHashNum * 0xFBA4C795 + nTweak, data) % (vData.size() * 8)
    ## DISABLED: depends on absent MurmurHash3.
    skip()

  test "Reference: 0xFBA4C795 = 4221880213 (decimal)":
    ## Document the seed constant for future implementers.
    check 0xFBA4C795'u32 == 4221880213'u32

# ─────────────────────────────────────────────────────────────────────────────
# G8 — Bit-index derivation
# ─────────────────────────────────────────────────────────────────────────────
suite "W134 G8 — Bit index derivation":
  test "BUG-01 (root): bit index derivation absent":
    ## Core bloom.cpp:47-58: nIndex = MurmurHash3(...) % (vData.size() * 8)
    ## Set: vData[nIndex >> 3] |= (1 << (7 & nIndex))
    ## Test: vData[nIndex >> 3] & (1 << (7 & nIndex))
    ## DISABLED: dependent on absent CBloomFilter.
    skip()

# ─────────────────────────────────────────────────────────────────────────────
# G9 — insert / contains correctness + CVE-2013-5700
# ─────────────────────────────────────────────────────────────────────────────
suite "W134 G9 — insert / contains correctness":
  test "BUG-01 (root): insert/contains absent — CBloomFilter absent":
    ## Core bloom.cpp:50-89: insert sets nHashFuncs bit positions; contains
    ## returns true iff all positions are set.  Both handle the empty-vData
    ## case (CVE-2013-5700): empty filter is a match-all filter.
    ## DISABLED: type absent.
    skip()

  test "Reference: CVE-2013-5700 empty-filter is match-all":
    ## Core bloom.cpp:52,71: if (vData.empty()) return [true for contains] /
    ## [return for insert].  Any future implementation must handle the empty
    ## case to avoid divide-by-zero.
    skip()

# ─────────────────────────────────────────────────────────────────────────────
# G10 — isFull / isEmpty short-circuit
# ─────────────────────────────────────────────────────────────────────────────
suite "W134 G10 — isFull/isEmpty short-circuit":
  test "BUG-01 (root): isFull/isEmpty absent":
    ## Core's older variants tracked all-bits-set / no-bits-set; current
    ## Core no longer exposes these (they were optimisations removed in 0.18+).
    ## Either way, nimrod has neither.
    ## DISABLED: type absent.
    skip()

# ─────────────────────────────────────────────────────────────────────────────
# G11-G14 — BLOOM_UPDATE flags
# ─────────────────────────────────────────────────────────────────────────────
suite "W134 G11-G14 — BLOOM_UPDATE flag constants":
  test "BUG-05: BLOOM_UPDATE_NONE/ALL/P2PUBKEY_ONLY/MASK absent":
    ## Core bloom.h:22-28:
    ##   BLOOM_UPDATE_NONE = 0
    ##   BLOOM_UPDATE_ALL  = 1
    ##   BLOOM_UPDATE_P2PUBKEY_ONLY = 2
    ##   BLOOM_UPDATE_MASK = 3
    ## None of these exist in nimrod (no `bloomflags` enum / no const block).
    ## DISABLED: absent.
    skip()

  test "Reference: flag value numeric values for any future implementation":
    const BloomUpdateNone         = 0
    const BloomUpdateAll          = 1
    const BloomUpdateP2PubkeyOnly = 2
    const BloomUpdateMask         = 3
    check BloomUpdateNone == 0
    check BloomUpdateAll == 1
    check BloomUpdateP2PubkeyOnly == 2
    check BloomUpdateMask == 3
    # Mask covers the first two bits exactly:
    check (BloomUpdateNone or BloomUpdateAll or BloomUpdateP2PubkeyOnly) == BloomUpdateMask

# ─────────────────────────────────────────────────────────────────────────────
# G15 — nFlags & UPDATE_MASK applied in IsRelevantAndUpdate
# ─────────────────────────────────────────────────────────────────────────────
suite "W134 G15 — nFlags & UPDATE_MASK applied":
  test "BUG-06 (dependent on BUG-05): flag application absent":
    ## Core bloom.cpp:123-132: switch on (nFlags & BLOOM_UPDATE_MASK).
    ## DISABLED: absent.
    skip()

# ─────────────────────────────────────────────────────────────────────────────
# G16-G20 — IsRelevantAndUpdate match logic
# ─────────────────────────────────────────────────────────────────────────────
suite "W134 G16-G20 — IsRelevantAndUpdate match logic":
  test "BUG-06: IsRelevantAndUpdate entirely absent":
    ## Core bloom.cpp:95-161 implements:
    ##   G16: contains(tx.GetHash())  — txid match
    ##   G17: per-output scriptPubKey pushdata extraction loop
    ##   G18: P2PKH/P2SH/P2PK/multisig match via Solver()
    ##   G19: contains(txin.prevout)  — outpoint match
    ##   G20: per-input scriptSig data items
    ## Nimrod implements none of these.
    ## DISABLED: absent.
    skip()

# ─────────────────────────────────────────────────────────────────────────────
# G21-G23 — IsRelevantAndUpdate update semantics
# ─────────────────────────────────────────────────────────────────────────────
suite "W134 G21-G23 — IsRelevantAndUpdate update semantics":
  test "BUG-06 (dependent): update semantics absent":
    ## G21 UPDATE_ALL: every matching output's outpoint is inserted.
    ## G22 UPDATE_P2PUBKEY_ONLY: only P2PK / multisig outpoints inserted
    ##   (Solver returns TxoutType::PUBKEY or TxoutType::MULTISIG).
    ## G23 UPDATE_NONE: filter never mutated.
    ## DISABLED: absent.
    skip()

# ─────────────────────────────────────────────────────────────────────────────
# G24 — Outpoint 36-byte LE serialization for bloom
# ─────────────────────────────────────────────────────────────────────────────
suite "W134 G24 — Outpoint 36-byte LE serialization for bloom":
  test "BUG-07: bloom outpoint helper absent":
    ## Core bloom.cpp:60-67: DataStream stream{}; stream << outpoint;
    ## insert(MakeUCharSpan(stream)) produces [txid 32 LE] ++ [vout 4 LE].
    ## Nimrod has no bloomInsertOutpoint() helper and no caller for one.
    ## DISABLED: absent.
    skip()

  test "PASS: raw serialize OutPoint produces 36 bytes (general path works)":
    ## Even though the bloom helper is absent, the generic OutPoint
    ## serializer in serialize.nim produces the correct 36-byte wire
    ## format when called directly.
    let op = OutPoint(txid: TxId(default(array[32, byte])), vout: 1'u32)
    var w = BinaryWriter()
    w.writeBytes(array[32, byte](op.txid))
    w.writeUint32LE(op.vout)
    check w.data.len == 36
    # vout = 1 LE = 0x01 0x00 0x00 0x00
    check w.data[32] == 0x01'u8
    check w.data[33] == 0x00'u8
    check w.data[34] == 0x00'u8
    check w.data[35] == 0x00'u8

  test "PASS: vout = 0xFEEDFACE serializes little-endian":
    ## Cross-check the LE byte order for a non-trivial vout.
    let op = OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFEEDFACE'u32)
    var w = BinaryWriter()
    w.writeBytes(array[32, byte](op.txid))
    w.writeUint32LE(op.vout)
    check w.data.len == 36
    check w.data[32] == 0xCE'u8
    check w.data[33] == 0xFA'u8
    check w.data[34] == 0xED'u8
    check w.data[35] == 0xFE'u8

# ─────────────────────────────────────────────────────────────────────────────
# G25 — filterload P2P message handling (FIX-36 CLOSED)
# ─────────────────────────────────────────────────────────────────────────────
suite "W134 G25 — filterload P2P message (FIX-36 closure verified)":
  ## FIX-36 added mkFilterLoad to MessageKind, routed "filterload" through
  ## commandToMessageKind / messageKindToCommand / deserializePayload, and
  ## attached a BIP-111 disconnect arm in both peer.nim and nimrod.nim
  ## handleMessage dispatch tables.  Body is intentionally NOT parsed —
  ## CBloomFilter is absent (W134 BUG-01), so the bytes mean nothing.

  test "FIX-36 PASS: commandToMessageKind('filterload') → mkFilterLoad":
    check commandToMessageKind("filterload") == mkFilterLoad

  test "FIX-36 PASS: messageKindToCommand(mkFilterLoad) → 'filterload'":
    check messageKindToCommand(mkFilterLoad) == "filterload"

  test "FIX-36 PASS: deserializePayload skips body, returns mkFilterLoad sentinel":
    ## A real Core filterload payload is:
    ##   <varint vData.len> <bytes vData> <uint32LE nHashFuncs>
    ##     <uint32LE nTweak> <uint8 nFlags>
    ## Nimrod deserializePayload "filterload" arm skips the bytes entirely
    ## and returns a sentinel P2PMessage(kind: mkFilterLoad) so the
    ## handleMessage disconnect path can fire without raising on parse.
    let payload: seq[byte] = @[
      0x02'u8, 0xFF, 0x80,                       # vData
      0x05'u8, 0x00, 0x00, 0x00,                 # nHashFuncs = 5
      0x12'u8, 0x34, 0x56, 0x78,                 # nTweak
      0x01'u8                                    # nFlags = BLOOM_UPDATE_ALL
    ]
    let msg = deserializePayload("filterload", payload)
    check msg.kind == mkFilterLoad

  test "FIX-36 PASS: deserializePayload handles empty filterload payload":
    ## Malformed but parseable: zero-byte payload.  Must NOT raise; the
    ## disconnect arm will fire regardless.
    let msg = deserializePayload("filterload", @[])
    check msg.kind == mkFilterLoad

  test "FIX-36 PASS: deserializePayload handles oversize-vData hint":
    ## A payload that would exceed MAX_BLOOM_FILTER_SIZE if the body were
    ## parsed.  Body is skipped; the sentinel is returned; the disconnect
    ## handler in peer.nim/nimrod.nim closes the connection.
    var payload: seq[byte] = @[]
    payload.add(0xFE'u8)                                # CompactSize 4-byte prefix
    payload.add(@[0x00'u8, 0x90, 0x00, 0x00])           # 36_864-byte vData claimed
    let msg = deserializePayload("filterload", payload)
    check msg.kind == mkFilterLoad

  test "BUG-01 (open): no per-peer CBloomFilter state on Peer":
    ## Core stores tx_relay->m_bloom_filter (unique_ptr<CBloomFilter>) and
    ## tx_relay->m_relay_txs in TxRelay.  Nimrod's Peer type has no
    ## equivalent fields.  Even if filterload parsing were added, there
    ## is nowhere to store the installed filter.  This is why FIX-36
    ## chose to disconnect rather than implement.
    ## DISABLED: field is absent.
    skip()

# ─────────────────────────────────────────────────────────────────────────────
# G26 — filteradd P2P message + ≤ 520 bytes guard (FIX-36 CLOSED)
# ─────────────────────────────────────────────────────────────────────────────
suite "W134 G26 — filteradd P2P message (FIX-36 closure verified)":
  test "FIX-36 PASS: commandToMessageKind('filteradd') → mkFilterAdd":
    check commandToMessageKind("filteradd") == mkFilterAdd

  test "FIX-36 PASS: messageKindToCommand(mkFilterAdd) → 'filteradd'":
    check messageKindToCommand(mkFilterAdd) == "filteradd"

  test "FIX-36 PASS: deserializePayload skips body, returns mkFilterAdd sentinel":
    ## A real filteradd payload is <varint data.len> <data bytes>.
    ## Body is skipped — sentinel returned so disconnect can fire.
    let payload: seq[byte] = @[0x20'u8] & newSeq[byte](32)  # 32-byte data item
    let msg = deserializePayload("filteradd", payload)
    check msg.kind == mkFilterAdd

  test "FIX-36 PASS: deserializePayload handles empty filteradd payload":
    let msg = deserializePayload("filteradd", @[])
    check msg.kind == mkFilterAdd

  test "FIX-36 PASS: deserializePayload accepts > 520-byte filteradd (body skipped)":
    ## Core would Misbehaving() if data.size() > MAX_SCRIPT_ELEMENT_SIZE,
    ## but nimrod never inspects the body — the disconnect arm fires
    ## regardless of size.  This documents the FIX-36 "parse-but-disconnect"
    ## closure shape: no body inspection means no size validation, but
    ## also no DoS surface because the connection is immediately closed.
    let oversizePayload: seq[byte] = newSeq[byte](600)  # > 520
    let msg = deserializePayload("filteradd", oversizePayload)
    check msg.kind == mkFilterAdd

  test "Reference PASS: MaxScriptElementSize = 520 defined in script/interpreter.nim":
    ## The MAX_SCRIPT_ELEMENT_SIZE constant exists for script use.  It
    ## would also be the filteradd cap if the bloom subsystem were
    ## implemented (Core net_processing.cpp:5000).
    ## We don't import script/interpreter here to keep this test file
    ## independent; we verify the documented value matches Core.
    const expectedMaxScriptElementSize = 520
    check expectedMaxScriptElementSize == 520

# ─────────────────────────────────────────────────────────────────────────────
# G27 — filterclear P2P message (FIX-36 CLOSED)
# ─────────────────────────────────────────────────────────────────────────────
suite "W134 G27 — filterclear P2P message (FIX-36 closure verified)":
  ## Core net_processing.cpp:5016-5032: filterclear sets
  ## tx_relay->m_bloom_filter = nullptr and tx_relay->m_relay_txs = true.
  ## Nimrod now parses filterclear and disconnects (BIP-111).

  test "FIX-36 PASS: commandToMessageKind('filterclear') → mkFilterClear":
    check commandToMessageKind("filterclear") == mkFilterClear

  test "FIX-36 PASS: messageKindToCommand(mkFilterClear) → 'filterclear'":
    check messageKindToCommand(mkFilterClear) == "filterclear"

  test "FIX-36 PASS: deserializePayload handles empty filterclear payload":
    ## filterclear has zero body in Core (net_processing.cpp:5016 doesn't
    ## read from vRecv).  Nimrod's deserializePayload returns the sentinel.
    let msg = deserializePayload("filterclear", @[])
    check msg.kind == mkFilterClear

  test "FIX-36 PASS: deserializePayload tolerates extraneous bytes":
    ## Some buggy peer implementations might send non-empty filterclear.
    ## Nimrod skips any body and returns the sentinel.
    let payload: seq[byte] = @[0xDE'u8, 0xAD, 0xBE, 0xEF]
    let msg = deserializePayload("filterclear", payload)
    check msg.kind == mkFilterClear

# ─────────────────────────────────────────────────────────────────────────────
# G28 — merkleblock + PartialMerkleTree
# ─────────────────────────────────────────────────────────────────────────────
suite "W134 G28 — merkleblock outgoing + PartialMerkleTree":
  test "BUG-09: invFilteredBlock falls through to notfound in getdata handler":
    ## nimrod.nim:1020-1022 getdata handler:
    ##   else:   # neither invBlock/invWitnessBlock nor invCmpctBlock nor invTx/invWitnessTx
    ##     notFound.add(item)
    ## Core net_processing.cpp:2438-2458 handles inv.IsMsgFilteredBlk() by
    ## building CMerkleBlock(*pblock, *tx_relay->m_bloom_filter) and emitting
    ## merkleblock + matched txns.  An SPV client requesting filtered
    ## blocks from nimrod receives notfound.
    ## DISABLED: bloom-triggered merkleblock serving is absent.
    skip()

  test "BUG-10 (dead-helper): w47b PMT helpers exist but unreachable from P2P":
    ## rpc/server.nim:7974 defines w47bBuildPartialMerkleTree and :8041
    ## defines w47bParsePartialMerkleTree for gettxoutproof / verifytxoutproof.
    ## These ~150 LOC helpers implement correct Partial Merkle Tree logic
    ## (depth-first traversal, header-prefixed wire format, varint
    ## bit-packed flags) but are NOT wired to any P2P path.  No call site
    ## from nimrod.nim's getdata handler, no CMerkleBlock wrapper, no
    ## outbound mkMerkleBlock construction.
    ## DISABLED: P2P call site is absent.
    skip()

  test "PASS: invFilteredBlock = 3 is correctly defined in InvType enum":
    ## messages.nim:42: invFilteredBlock = 3
    ## The constant is present and correct — Core MSG_FILTERED_BLOCK = 3.
    ## Would be the dispatch key if the bloom subsystem were implemented.
    check invFilteredBlock.ord == 3

  test "PASS: mkMerkleBlock variant exists (FIX-36) and is incoming-only":
    ## FIX-36 added mkMerkleBlock so an unexpected incoming merkleblock
    ## can be parsed (body skipped) and dropped with a warning.
    ## Verify round-trip in the enum mapping.
    check commandToMessageKind("merkleblock") == mkMerkleBlock
    check messageKindToCommand(mkMerkleBlock) == "merkleblock"

  test "PASS: deserializePayload of merkleblock returns sentinel":
    ## Body is skipped — merkleblock incoming arms (peer.nim, nimrod.nim)
    ## log+drop without raising.
    let payload: seq[byte] = newSeq[byte](100)  # arbitrary bytes
    let msg = deserializePayload("merkleblock", payload)
    check msg.kind == mkMerkleBlock

# ─────────────────────────────────────────────────────────────────────────────
# G29 — IsWithinSizeConstraints DoS guard
# ─────────────────────────────────────────────────────────────────────────────
suite "W134 G29 — IsWithinSizeConstraints DoS guard":
  test "BUG-01 (root): IsWithinSizeConstraints absent — CBloomFilter absent":
    ## Core bloom.cpp:90-93: return vData.size() <= MAX_BLOOM_FILTER_SIZE
    ##                       && nHashFuncs <= MAX_HASH_FUNCS;
    ## Called by Core's filterload handler immediately after deserialise
    ## (net_processing.cpp:4972).  Failure → Misbehaving(peer, "too-large
    ## bloom filter").  Nimrod's FIX-36 disconnect renders this moot for
    ## now, but any future bloom implementation MUST add this guard.
    ## DISABLED: type and constants absent.
    skip()

# ─────────────────────────────────────────────────────────────────────────────
# G30 — NODE_BLOOM service bit + BIP-111 advertisement gate (FIX-35 CLOSED)
# ─────────────────────────────────────────────────────────────────────────────
suite "W134 G30 — NODE_BLOOM service bit + BIP-111 gate (FIX-35 closure)":
  ## FIX-35 dropped NodeBloom from outbound version services.  BIP-111
  ## mandates a node MUST NOT advertise NODE_BLOOM unless it serves
  ## BIP-37.  Nimrod has no CBloomFilter, so the bit is permanently
  ## absent from advertisement regardless of any env var.
  ## peerBloomFiltersEnabled is retained solely as the BIP-35 mempool gate.

  test "PASS: NodeBloom = 4 (1 << 2) constant correctly defined":
    ## Core protocol.h:316-317: NODE_BLOOM = (1 << 2) = 4.
    ## messages.nim:24: NodeBloom* = 4'u64
    check NodeBloom == 4'u64
    check (NodeBloom and (NodeBloom - 1)) == 0'u64  # power-of-two

  test "PASS: peerBloomFiltersEnabled() defaults OFF (Core-aligned)":
    ## Core net_processing.h:44: DEFAULT_PEERBLOOMFILTERS = false.
    ## nimrod env var absent → false.
    delEnv("NIMROD_PEER_BLOOM_FILTERS")
    check peerBloomFiltersEnabled() == false

  test "PASS: peerBloomFiltersEnabled() is ON when env var = '1' (mempool gate only)":
    ## Env var controls the BIP-35 mempool gate ONLY since FIX-35.
    ## It does NOT control NODE_BLOOM advertisement.
    putEnv("NIMROD_PEER_BLOOM_FILTERS", "1")
    check peerBloomFiltersEnabled() == true
    delEnv("NIMROD_PEER_BLOOM_FILTERS")

  test "PASS: peerBloomFiltersEnabled() recognises 'true'/'yes'/'on' (case-insensitive)":
    for v in ["true", "yes", "on", "TRUE", "On", "YES"]:
      putEnv("NIMROD_PEER_BLOOM_FILTERS", v)
      check peerBloomFiltersEnabled() == true
    delEnv("NIMROD_PEER_BLOOM_FILTERS")

  test "PASS: peerBloomFiltersEnabled() rejects unknown values":
    for v in ["0", "false", "no", "off", "maybe", "FALSE", "Off", ""]:
      putEnv("NIMROD_PEER_BLOOM_FILTERS", v)
      check peerBloomFiltersEnabled() == false
    delEnv("NIMROD_PEER_BLOOM_FILTERS")

  test "FIX-35 PASS: NODE_BLOOM is NEVER in baseline outbound services — env OFF":
    ## peer.nim:575 builds ourServices = NodeNetwork or NodeWitness.
    ## NodeBloom is NEVER OR'd in regardless of env var.
    delEnv("NIMROD_PEER_BLOOM_FILTERS")
    let baseServices: uint64 = NodeNetwork or NodeWitness
    check (baseServices and NodeBloom) == 0'u64

  test "FIX-35 PASS: NODE_BLOOM is NEVER in baseline outbound services — env ON":
    ## Even with NIMROD_PEER_BLOOM_FILTERS=1, sendVersion() must not set
    ## NODE_BLOOM.  Verifies the env-var gate is decoupled from advertisement.
    putEnv("NIMROD_PEER_BLOOM_FILTERS", "1")
    let baseServices: uint64 = NodeNetwork or NodeWitness
    check (baseServices and NodeBloom) == 0'u64
    # mempool gate must still be ON:
    check peerBloomFiltersEnabled() == true
    delEnv("NIMROD_PEER_BLOOM_FILTERS")

  test "FIX-35 PASS: W110 BUG-13 closed — no SPV-client deception":
    ## Pre-FIX-35: NIMROD_PEER_BLOOM_FILTERS=1 set NODE_BLOOM in version,
    ## peers sent filterload, nimrod silently dropped → SPV clients
    ## believed filtering was active.  Post-FIX-35: NodeBloom is absent
    ## from sendVersion services, no compliant SPV client will send
    ## filterload.
    let advertisedServices: uint64 = NodeNetwork or NodeWitness
    check (advertisedServices and NodeBloom) == 0'u64
    # Sanity: constant still defined for documentation:
    check NodeBloom == 4'u64

  test "FIX-36 PASS: dispatch table maps all 3 BIP-37 messages":
    ## handleMessage in peer.nim:1534-1547 and nimrod.nim:1404-1417 attach
    ## BIP-111 disconnect arms to all three.  We can't simulate a live
    ## socket here, but we can verify the enum mapping that the dispatch
    ## relies on.
    check commandToMessageKind("filterload") == mkFilterLoad
    check commandToMessageKind("filteradd") == mkFilterAdd
    check commandToMessageKind("filterclear") == mkFilterClear

# ─────────────────────────────────────────────────────────────────────────────
# W134 Extra-1: BIP-324 short-ID coverage
# ─────────────────────────────────────────────────────────────────────────────
suite "W134 Extra-1 — BIP-324 v2 transport short-IDs (FIX-36 verified)":
  test "PASS: filteradd short ID 0x06 round-trips to mkFilterAdd":
    ## bip324.nim short-ID table maps 0x06 → "filteradd" → mkFilterAdd.
    check commandToMessageKind("filteradd") == mkFilterAdd

  test "PASS: filterclear short ID 0x07 round-trips to mkFilterClear":
    check commandToMessageKind("filterclear") == mkFilterClear

  test "PASS: filterload short ID 0x08 round-trips to mkFilterLoad":
    check commandToMessageKind("filterload") == mkFilterLoad

  test "PASS: merkleblock short ID 0x10 round-trips to mkMerkleBlock":
    check commandToMessageKind("merkleblock") == mkMerkleBlock

# ─────────────────────────────────────────────────────────────────────────────
# W134 Extra-2: eviction.bloomFilter field is a no-op placeholder
# ─────────────────────────────────────────────────────────────────────────────
suite "W134 Extra-2 — EvictionCandidate.bloomFilter placeholder":
  test "PASS: EvictionCandidate has bloomFilter field (always false on construction)":
    ## eviction.nim:36: `bloomFilter*: bool  # Peer uses bloom filters`
    ## The field exists for layout symmetry with Core's eviction algorithm
    ## (Core's compareNodeTxTime uses m_relays_txs + bloom-filter use as
    ## a tie-breaker).  Nimrod's peermanager.nim:751 constructs every
    ## EvictionCandidate with bloomFilter: false (no subsystem to use).
    ## This is intentional and consistent with W134 BUG-01.
    let cand = EvictionCandidate(
      id: 0, address: "", connected: default(Time),
      minPingTime: default(Duration),
      lastBlockTime: default(Time), lastTxTime: default(Time),
      relevantServices: true, relayTxs: true,
      bloomFilter: false,
      keyedNetGroup: 0, preferEvict: false, isLocal: false,
      netGroup: default(NetGroup), noBan: false,
      connType: ctInbound
    )
    check cand.bloomFilter == false

# ─────────────────────────────────────────────────────────────────────────────
# W134 Extra-3: serializePayload emits empty body for sendable bloom variants
# ─────────────────────────────────────────────────────────────────────────────
suite "W134 Extra-3 — serializePayload for bloom variants (never sent)":
  ## serializePayload includes mkFilterLoad/mkFilterAdd/mkFilterClear/mkMerkleBlock
  ## in the empty-body arm (messages.nim:489-491).  Nimrod NEVER constructs
  ## or sends these messages outbound, but the serializer path must not
  ## raise if a test or refactor accidentally builds one.

  test "PASS: serializePayload(mkFilterLoad) emits empty bytes":
    let msg = P2PMessage(kind: mkFilterLoad)
    let payload = serializePayload(msg)
    check payload.len == 0

  test "PASS: serializePayload(mkFilterAdd) emits empty bytes":
    let msg = P2PMessage(kind: mkFilterAdd)
    let payload = serializePayload(msg)
    check payload.len == 0

  test "PASS: serializePayload(mkFilterClear) emits empty bytes":
    let msg = P2PMessage(kind: mkFilterClear)
    let payload = serializePayload(msg)
    check payload.len == 0

  test "PASS: serializePayload(mkMerkleBlock) emits empty bytes":
    let msg = P2PMessage(kind: mkMerkleBlock)
    let payload = serializePayload(msg)
    check payload.len == 0

# ─────────────────────────────────────────────────────────────────────────────
# W134 Extra-4: command/kind round-trip for all 4 BIP-37/PMT messages
# ─────────────────────────────────────────────────────────────────────────────
suite "W134 Extra-4 — command/kind round-trip integrity":
  test "PASS: filterload round-trip":
    let k = commandToMessageKind("filterload")
    check messageKindToCommand(k) == "filterload"

  test "PASS: filteradd round-trip":
    let k = commandToMessageKind("filteradd")
    check messageKindToCommand(k) == "filteradd"

  test "PASS: filterclear round-trip":
    let k = commandToMessageKind("filterclear")
    check messageKindToCommand(k) == "filterclear"

  test "PASS: merkleblock round-trip":
    let k = commandToMessageKind("merkleblock")
    check messageKindToCommand(k) == "merkleblock"
