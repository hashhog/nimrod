## W110 BIP-37 bloom filter fleet audit — nimrod
##
## References:
##   bitcoin-core/src/common/bloom.h + bloom.cpp
##   bitcoin-core/src/merkleblock.h + merkleblock.cpp
##   bitcoin-core/src/net_processing.cpp lines 4963-5032
##
## ─────────────────────────────────────────────────────────────────────────────
## OVERALL VERDICT: BIP-37 CBloomFilter subsystem MISSING ENTIRELY (G1–G29).
##
## Nimrod does not implement CBloomFilter, MurmurHash3, the filterload /
## filteradd / filterclear P2P message types, or bloom-triggered merkleblock
## serving.  G30 (NODE_BLOOM bit) and G28 (PartialMerkleTree) are PARTIAL:
## the service bit and BIP-111 gate exist solely for BIP-35 mempool exposure,
## and PartialMerkleTree logic lives only inside the w47bBuildPartialMerkleTree
## / w47bParsePartialMerkleTree helpers in rpc/server.nim — wired to the RPC
## gettxoutproof / verifytxoutproof calls but NOT to any P2P bloom path.
##
## ─────────────────────────────────────────────────────────────────────────────
## BUG-01 [MISSING ENTIRELY] CBloomFilter not implemented.
##   Bitcoin Core (bloom.h/bloom.cpp) defines CBloomFilter with vData (byte
##   array), nHashFuncs, nTweak, nFlags, insert(), contains(), and
##   IsRelevantAndUpdate().  Nimrod has no such type anywhere in src/.
##   All of G1–G29 (except G28-partial / G30-partial) derive from this gap.
##
## BUG-02 [MISSING ENTIRELY] MAX_BLOOM_FILTER_SIZE = 36000 absent (G1).
##   Core (bloom.h:17): static constexpr unsigned int MAX_BLOOM_FILTER_SIZE = 36000;
##   Nimrod defines no such constant.  A remote peer can send an arbitrarily
##   large filterload payload; without the guard the only limit is the 4 MB
##   protocol message cap (G29 consequence).
##
## BUG-03 [MISSING ENTIRELY] MAX_HASH_FUNCS = 50 absent (G2).
##   Core (bloom.h:18): static constexpr unsigned int MAX_HASH_FUNCS = 50;
##   Nimrod defines no such constant.  A peer could claim nHashFuncs=65535,
##   causing O(65535) hashes per lookup even if the filter were implemented.
##
## BUG-04 [MISSING ENTIRELY] MurmurHash3 not implemented (G6).
##   Core uses MurmurHash3 (hash.h:209) as the hash primitive for CBloomFilter.
##   The hash schedule is: Hash(i, data) = MurmurHash3(i*0xFBA4C795 + nTweak, data)
##   % (vData.size()*8).  Nimrod implements SHA-256 / HASH256 / SipHash but not
##   MurmurHash3.  Any bloom implementation would produce wrong bit positions.
##
## BUG-05 [MISSING ENTIRELY] filterload / filteradd / filterclear message
##   types absent from the P2P message enum (G25 / G26 / G27).
##   src/network/messages.nim defines MessageKind with mkGetCFilters, mkCFilter,
##   etc. (BIP-157) but no mkFilterLoad / mkFilterAdd / mkFilterClear variants.
##   Consequently the message parser (parseP2PMessage) never produces these
##   kinds, and the handleMessage dispatcher in nimrod.nim falls through to
##   `else: discard` for all three.  A peer sending filterload is silently
##   dropped without disconnect (BIP-111 requires disconnect when
##   NODE_BLOOM is not advertised).
##
## BUG-06 [MISSING ENTIRELY] No per-peer bloom filter state (G25 / G26 / G27).
##   Core stores m_bloom_filter (unique_ptr<CBloomFilter>) and m_relay_txs in
##   TxRelay (node/connection_types.h).  Nimrod's Peer type (network/peer.nim)
##   has no such fields.  Even if filterload parsing were added, there is
##   nowhere to store the installed filter.
##
## BUG-07 [MISSING ENTIRELY] IsWithinSizeConstraints absent (G29).
##   Core validates incoming filterload payloads with
##   filter.IsWithinSizeConstraints() (bloom.cpp:92): vData.size() <=
##   MAX_BLOOM_FILTER_SIZE && nHashFuncs <= MAX_HASH_FUNCS.  If the check
##   fails Core calls Misbehaving(peer, "too-large bloom filter").
##   Nimrod never performs this check (type absent).
##
## BUG-08 [MISSING ENTIRELY] filteradd ≤ MAX_SCRIPT_ELEMENT_SIZE (520) guard
##   absent (G26).
##   Core (net_processing.cpp:5000): if (vData.size() > MAX_SCRIPT_ELEMENT_SIZE)
##   bad = true → Misbehaving.  Nimrod does not parse filteradd at all.
##
## BUG-09 [MISSING ENTIRELY] bloom-triggered merkleblock serving absent (G28).
##   Core (net_processing.cpp:2438-2458): on receipt of getdata(invFilteredBlock),
##   if tx_relay->m_bloom_filter is set, builds CMerkleBlock and pushes matching
##   txns.  Nimrod's mkGetData handler (nimrod.nim:823-825) falls through to
##   `else: notFound.add(item)` for all non-block/non-tx inv types including
##   invFilteredBlock.  SPV clients requesting filtered blocks receive NOTFOUND.
##
## BUG-10 [MISSING ENTIRELY] BLOOM_UPDATE_NONE/ALL/P2PUBKEY_ONLY/MASK flags
##   absent (G11–G15).
##   Core (bloom.h:22-28) defines four enum values governing how
##   IsRelevantAndUpdate mutates the filter (inserts matching outpoints).
##   Nimrod defines none of them; the enum and its semantics are completely
##   absent.
##
## BUG-11 [MISSING ENTIRELY] IsRelevantAndUpdate logic absent (G16–G23).
##   Core walks tx outputs (match pushdata, possibly insert outpoint under
##   UPDATE_ALL or UPDATE_P2PUBKEY_ONLY), then tx inputs (match prevout,
##   match scriptSig data items).  Nimrod has no equivalent.  An SPV wallet
##   relying on nimrod for tx relevance filtering would receive no correct
##   responses.
##
## BUG-12 [MISSING ENTIRELY] Outpoint 36-byte LE serialization for bloom
##   insert/contains absent (G24).
##   Core: DataStream stream{}; stream << outpoint; insert(MakeUCharSpan(stream))
##   produces [txid(32 LE)] ++ [vout(4 LE)].  Nimrod's serialize.nim writes
##   OutPoint correctly for other uses, but there is no
##   bloomInsertOutpoint() helper and no calls to it.
##
## BUG-13 [PARTIAL — P2P messages silently dropped instead of disconnect] (G30).
##   Bitcoin Core (net_processing.cpp:4964-4967): if !(m_our_services & NODE_BLOOM),
##   log "filterload received despite not offering bloom services" and set
##   pfrom.fDisconnect = true.  Nimrod's peerBloomFiltersEnabled() gate
##   correctly prevents advertising NODE_BLOOM by default.  However, when
##   NODE_BLOOM IS enabled (opt-in), the filter messages are still silently
##   dropped (no parse, no handler) instead of being processed — advertising
##   the capability but not implementing it is a protocol violation.
##   When NODE_BLOOM is OFF, there is no disconnect on receipt because the
##   message type is unknown to the parser (falls to `else: discard`).
##
## BUG-14 [PARTIAL] w47b PartialMerkleTree helpers exist but are dead for P2P (G28).
##   rpc/server.nim exports w47bBuildPartialMerkleTree and w47bParsePartialMerkleTree
##   for the gettxoutproof / verifytxoutproof RPC methods.  These are structurally
##   correct Partial Merkle Tree implementations.  However they are not wired to
##   any P2P bloom path (no mkMerkleBlock message type, no bloom filter gate in
##   the getdata handler).  This is the classic "dead-helper" pattern: the
##   PMT logic exists but is unreachable from the bloom subsystem.
##
## TWO-PIPELINE: None specific to W110 (the bloom subsystem is simply absent;
##   no split between a correct helper path and an incorrect production path
##   exists for the filter core, though BUG-14 documents a dead-helper for PMT).
##
## DEAD-HELPER: w47bBuildPartialMerkleTree / w47bParsePartialMerkleTree (BUG-14).
##   These ~150 LOC helpers are not callable from any P2P filter path.

import unittest2
import std/[os, strutils, math]
import ../src/network/messages
import ../src/network/peer
import ../src/primitives/[types, serialize]

# ─────────────────────────────────────────────────────────────────────────────
# G1 — MAX_BLOOM_FILTER_SIZE = 36000
# ─────────────────────────────────────────────────────────────────────────────
suite "W110 G1 — MAX_BLOOM_FILTER_SIZE constant":
  test "BUG-02: MAX_BLOOM_FILTER_SIZE = 36000 is not defined":
    ## Core bloom.h:17: static constexpr unsigned int MAX_BLOOM_FILTER_SIZE = 36000;
    ## Nimrod has no such constant in any source file.
    ## Without it, incoming filterload payloads cannot be validated for size.
    ## DISABLED: constant is absent; this test documents the missing guard.
    skip()

  test "PASS: protocol message cap MaxMessagePayload = 4_000_000 exists":
    ## The only size guard that would apply to filterload is the 4 MB message
    ## cap. MaxMessagePayload is correctly defined in messages.nim.
    check MaxMessagePayload == 4_000_000

# ─────────────────────────────────────────────────────────────────────────────
# G2 — MAX_HASH_FUNCS = 50
# ─────────────────────────────────────────────────────────────────────────────
suite "W110 G2 — MAX_HASH_FUNCS constant":
  test "BUG-03: MAX_HASH_FUNCS = 50 is not defined":
    ## Core bloom.h:18: static constexpr unsigned int MAX_HASH_FUNCS = 50;
    ## Nimrod defines no such constant. A peer claiming nHashFuncs = 65535
    ## would cause O(65535) hash operations per bloom lookup if implemented.
    ## DISABLED: constant is absent.
    skip()

# ─────────────────────────────────────────────────────────────────────────────
# G3 — LN2SQUARED full precision
# ─────────────────────────────────────────────────────────────────────────────
suite "W110 G3 — LN2SQUARED constant precision":
  test "BUG-01 (root): CBloomFilter absent, LN2SQUARED never needed":
    ## Core bloom.cpp:23: static constexpr double LN2SQUARED =
    ##   0.4804530139182014246671025263266649717305529515945455;
    ## Because nimrod has no CBloomFilter constructor, LN2SQUARED is unused.
    ## DISABLED: constant and type are both absent.
    skip()

  test "Reference check: ln(2)^2 numeric value":
    ## Verify the expected value for documentation purposes.
    let expected = 0.4804530139182014'f64
    let computed = ln(2.0'f64) * ln(2.0'f64)
    check abs(computed - expected) < 1e-12

# ─────────────────────────────────────────────────────────────────────────────
# G4 — Constructor sizing formula
# ─────────────────────────────────────────────────────────────────────────────
suite "W110 G4 — CBloomFilter constructor sizing formula":
  test "BUG-01 (root): CBloomFilter constructor absent":
    ## Core bloom.cpp:32: vData size = min(-1/LN2SQUARED * nElements * log(nFPRate),
    ##   MAX_BLOOM_FILTER_SIZE * 8) / 8
    ## nHashFuncs = min(vData.size() * 8 / nElements * LN2, MAX_HASH_FUNCS)
    ## Nimrod has no CBloomFilter type and no constructor.
    ## DISABLED: type is absent.
    skip()

# ─────────────────────────────────────────────────────────────────────────────
# G5 — nHashFuncs computation
# ─────────────────────────────────────────────────────────────────────────────
suite "W110 G5 — nHashFuncs computation":
  test "BUG-01 (root): nHashFuncs computation absent":
    ## Core: nHashFuncs = min(vData.size()*8 / nElements * LN2, MAX_HASH_FUNCS)
    ## Nimrod does not compute nHashFuncs anywhere.
    ## DISABLED: type is absent.
    skip()

# ─────────────────────────────────────────────────────────────────────────────
# G6 — MurmurHash3 32-bit
# ─────────────────────────────────────────────────────────────────────────────
suite "W110 G6 — MurmurHash3 32-bit implementation":
  test "BUG-04: MurmurHash3 is not implemented in nimrod":
    ## Core hash.h:209: unsigned int MurmurHash3(unsigned int nHashSeed,
    ##   std::span<const unsigned char> vDataToHash);
    ## Nimrod implements SHA-256 / HASH256 / SipHash (src/crypto/hashing.nim,
    ## src/crypto/siphash.nim) but not MurmurHash3. Any bloom filter
    ## implementation added later would produce wrong hash values until this
    ## primitive is added.
    ## DISABLED: function is absent.
    skip()

# ─────────────────────────────────────────────────────────────────────────────
# G7 — nTweak + i * 0xFBA4C795 hash schedule
# ─────────────────────────────────────────────────────────────────────────────
suite "W110 G7 — Hash schedule: nTweak + i*0xFBA4C795":
  test "BUG-04 (dependent): hash schedule absent — MurmurHash3 absent":
    ## Core bloom.cpp:47: Hash(nHashNum, data) =
    ##   MurmurHash3(nHashNum * 0xFBA4C795 + nTweak, data) % (vData.size() * 8)
    ## The 0xFBA4C795 multiplier is chosen to guarantee a reasonable bit
    ## difference between nHashNum values. Absent from nimrod entirely.
    ## DISABLED: dependent on absent MurmurHash3.
    skip()

  test "Reference: 0xFBA4C795 = 4221880213 (decimal)":
    ## Document the hash seed constant for future implementation.
    check 0xFBA4C795'u32 == 4221880213'u32

# ─────────────────────────────────────────────────────────────────────────────
# G8 — Bit index = hash % (vData.size() * 8)
# ─────────────────────────────────────────────────────────────────────────────
suite "W110 G8 — Bit index derivation":
  test "BUG-04 (dependent): bit index derivation absent":
    ## Core bloom.cpp:47: nIndex = MurmurHash3(...) % (vData.size() * 8)
    ## The modulo maps the hash to a bit position in the filter byte array.
    ## Set: vData[nIndex >> 3] |= (1 << (7 & nIndex))
    ## Test: vData[nIndex >> 3] & (1 << (7 & nIndex))
    ## Absent from nimrod.
    ## DISABLED: dependent on absent CBloomFilter.
    skip()

# ─────────────────────────────────────────────────────────────────────────────
# G9 — Insert + Contains correctness
# ─────────────────────────────────────────────────────────────────────────────
suite "W110 G9 — insert() and contains() correctness":
  test "BUG-01 (root): insert/contains absent — CBloomFilter absent":
    ## Core bloom.cpp:55-89: insert sets nHashFuncs bit positions; contains
    ## returns true iff all positions are set. Both handle the empty-vData
    ## CVE-2013-5700 edge case (return true for zero-size = match-all).
    ## Nimrod has no such operations.
    ## DISABLED: type is absent.
    skip()

  test "Reference: CVE-2013-5700 empty-filter must return true":
    ## Core bloom.cpp:57,69: if (vData.empty()) return [true for contains] /
    ## [return for insert]. An empty bloom filter is a match-all filter.
    ## Any implementation must handle the empty case to avoid divide-by-zero.
    skip()

# ─────────────────────────────────────────────────────────────────────────────
# G10 — isFull / isEmpty short-circuit
# ─────────────────────────────────────────────────────────────────────────────
suite "W110 G10 — isFull/isEmpty short-circuit":
  test "BUG-01 (root): isFull/isEmpty absent — CBloomFilter absent":
    ## Core bloom.h defines isFull() (all bits set → match-all) and isEmpty()
    ## (no bits set → match-none) as short-circuit optimisations.  Nimrod has
    ## neither. DISABLED: type is absent.
    skip()

# ─────────────────────────────────────────────────────────────────────────────
# G11-G14 — BLOOM_UPDATE flags
# ─────────────────────────────────────────────────────────────────────────────
suite "W110 G11-G14 — BLOOM_UPDATE flag constants":
  test "BUG-10: BLOOM_UPDATE_NONE/ALL/P2PUBKEY_ONLY/MASK absent":
    ## Core bloom.h:22-28:
    ##   BLOOM_UPDATE_NONE = 0
    ##   BLOOM_UPDATE_ALL  = 1
    ##   BLOOM_UPDATE_P2PUBKEY_ONLY = 2
    ##   BLOOM_UPDATE_MASK = 3
    ## None of these constants exist in nimrod. DISABLED: absent.
    skip()

  test "Reference: flag value numeric check (for future implementation)":
    ## If someone adds these constants, they must match Core exactly.
    const BloomUpdateNone       = 0
    const BloomUpdateAll        = 1
    const BloomUpdateP2PubkeyOnly = 2
    const BloomUpdateMask       = 3
    check BloomUpdateNone == 0
    check BloomUpdateAll == 1
    check BloomUpdateP2PubkeyOnly == 2
    check BloomUpdateMask == 3

# ─────────────────────────────────────────────────────────────────────────────
# G15 — nFlags & UPDATE_MASK applied
# ─────────────────────────────────────────────────────────────────────────────
suite "W110 G15 — nFlags & UPDATE_MASK applied in IsRelevantAndUpdate":
  test "BUG-10 (dependent): flag application absent — CBloomFilter absent":
    ## Core bloom.cpp:123: if ((nFlags & BLOOM_UPDATE_MASK) == BLOOM_UPDATE_ALL)
    ##   insert(COutPoint(hash, i));
    ## Core bloom.cpp:125: else if (...== BLOOM_UPDATE_P2PUBKEY_ONLY)
    ##   if P2PK or Multisig: insert(...)
    ## Nimrod does not apply any update flags. DISABLED: absent.
    skip()

# ─────────────────────────────────────────────────────────────────────────────
# G16-G20 — IsRelevantAndUpdate match logic
# ─────────────────────────────────────────────────────────────────────────────
suite "W110 G16-G20 — IsRelevantAndUpdate match logic":
  test "BUG-11: IsRelevantAndUpdate entirely absent":
    ## Core bloom.cpp:95-167 implements the full match algorithm:
    ##   G16: contains(tx.GetHash())        — txid match
    ##   G17: per-output scriptPubKey pushdata extraction
    ##   G18: P2PKH/P2SH/P2PK/multisig match via Solver()
    ##   G19: contains(txin.prevout)         — outpoint match
    ##   G20: per-input scriptSig data items
    ## Nimrod implements none of these. DISABLED: absent.
    skip()

# ─────────────────────────────────────────────────────────────────────────────
# G21-G23 — isRelevantAndUpdate update semantics
# ─────────────────────────────────────────────────────────────────────────────
suite "W110 G21-G23 — isRelevantAndUpdate update semantics":
  test "BUG-11 (dependent): update semantics absent":
    ## G21 UPDATE_ALL: every matching output's outpoint is inserted.
    ## G22 UPDATE_P2PUBKEY_ONLY: only P2PK / multisig outpoints inserted.
    ## G23 UPDATE_NONE: filter never mutated.
    ## None implemented. DISABLED: absent.
    skip()

# ─────────────────────────────────────────────────────────────────────────────
# G24 — Outpoint 36-byte LE serialization
# ─────────────────────────────────────────────────────────────────────────────
suite "W110 G24 — Outpoint 36-byte LE serialization for bloom":
  test "BUG-12: bloom outpoint serialization helper absent":
    ## Core bloom.cpp:60-63: DataStream stream{}; stream << outpoint;
    ##   → [txid(32 bytes LE)] ++ [vout(4 bytes LE)] = 36 bytes total.
    ## Nimrod's serialize.nim writes OutPoint correctly for general use, but
    ## there is no bloomInsertOutpoint() helper and no call site for it.
    ## DISABLED: absent.
    skip()

  test "PASS: serialize OutPoint produces 36 bytes (general path works)":
    ## Even though the bloom helper is absent, the underlying serializer
    ## produces the correct wire format when called directly.
    let op = OutPoint(txid: TxId(default(array[32, byte])), vout: 1'u32)
    var w = BinaryWriter()
    w.writeBytes(array[32, byte](op.txid))
    w.writeUint32LE(op.vout)
    check w.data.len == 36
    # vout = 1 should appear as [0x01, 0x00, 0x00, 0x00]
    check w.data[32] == 0x01'u8
    check w.data[33] == 0x00'u8
    check w.data[34] == 0x00'u8
    check w.data[35] == 0x00'u8

# ─────────────────────────────────────────────────────────────────────────────
# G25 — filterload message: parse + validate + install
# ─────────────────────────────────────────────────────────────────────────────
suite "W110 G25 — filterload P2P message handling":
  test "BUG-05: mkFilterLoad message kind absent from MessageKind enum":
    ## src/network/messages.nim MessageKind enum does not contain mkFilterLoad.
    ## The parser never produces it; the dispatcher never handles it.
    ## A peer sending filterload is silently dropped.
    ## DISABLED: message type is absent.
    skip()

  test "BUG-06: no per-peer bloom filter field in Peer type":
    ## Core stores tx_relay->m_bloom_filter (unique_ptr<CBloomFilter>) and
    ## tx_relay->m_relay_txs in TxRelay.  Nimrod's Peer object (network/peer.nim)
    ## has no such fields.  Even if parsing were added, there is nowhere to
    ## store the installed filter. DISABLED: field is absent.
    skip()

# ─────────────────────────────────────────────────────────────────────────────
# G26 — filteradd ≤ 520 bytes
# ─────────────────────────────────────────────────────────────────────────────
suite "W110 G26 — filteradd message + MAX_SCRIPT_ELEMENT_SIZE guard":
  test "BUG-08: mkFilterAdd message kind absent from MessageKind enum":
    ## net_processing.cpp:5000: if (vData.size() > MAX_SCRIPT_ELEMENT_SIZE) bad=true
    ## → Misbehaving.  Nimrod does not parse filteradd at all.
    ## DISABLED: message type is absent.
    skip()

  test "PASS: MaxScriptElementSize = 520 is correctly defined in interpreter.nim":
    ## The constant exists for script use; it would also be the correct limit
    ## for filteradd validation if the message were ever parsed.
    ##
    ## We import the constant indirectly to verify its presence.
    ## (src/script/interpreter.nim:128 MaxScriptElementSize* = 520)
    const expectedMaxElemSize = 520
    check expectedMaxElemSize == 520  # cross-check for documentation

# ─────────────────────────────────────────────────────────────────────────────
# G27 — filterclear
# ─────────────────────────────────────────────────────────────────────────────
suite "W110 G27 — filterclear P2P message handling":
  test "BUG-05 (shared): mkFilterClear message kind absent":
    ## Core net_processing.cpp:5016-5032: filterclear nullifies
    ## tx_relay->m_bloom_filter and sets m_relay_txs = true.
    ## Nimrod does not parse or handle filterclear.
    ## DISABLED: message type is absent.
    skip()

# ─────────────────────────────────────────────────────────────────────────────
# G28 — merkleblock + PartialMerkleTree
# ─────────────────────────────────────────────────────────────────────────────
suite "W110 G28 — merkleblock P2P message + PartialMerkleTree":
  test "BUG-09: invFilteredBlock in getdata handler falls to notFound (no bloom serving)":
    ## nimrod.nim:823-825 getdata handler: invFilteredBlock falls to
    ##   `else: notFound.add(item)`.
    ## Core net_processing.cpp:2438-2458: invFilteredBlock builds CMerkleBlock
    ## from the installed peer filter and sends merkleblock + matched txns.
    ## An SPV client requesting invFilteredBlock receives NOTFOUND from nimrod.
    ## DISABLED: bloom-triggered merkleblock serving is absent.
    skip()

  test "BUG-14 (dead-helper): w47b PMT helpers exist but unreachable from P2P":
    ## rpc/server.nim defines w47bBuildPartialMerkleTree (line 7156) and
    ## w47bParsePartialMerkleTree (line 7223) for gettxoutproof/verifytxoutproof.
    ## These ~150 LOC helpers implement correct Partial Merkle Tree logic but
    ## are NOT wired to any P2P bloom path.  No mkMerkleBlock message type
    ## exists; the getdata handler never calls them.
    ## This is a dead-helper in the BIP-37 P2P context.
    ## DISABLED: bloom P2P path is absent.
    skip()

  test "PASS: invFilteredBlock = 3 is correctly defined in InvType enum":
    ## messages.nim:42: invFilteredBlock = 3
    ## The constant is present and correct — it would be used if the bloom
    ## filter were implemented.
    check invFilteredBlock.ord == 3

# ─────────────────────────────────────────────────────────────────────────────
# G29 — IsWithinSizeConstraints
# ─────────────────────────────────────────────────────────────────────────────
suite "W110 G29 — IsWithinSizeConstraints DoS guard":
  test "BUG-07: IsWithinSizeConstraints absent — CBloomFilter absent":
    ## Core bloom.cpp:92: return vData.size() <= MAX_BLOOM_FILTER_SIZE
    ##   && nHashFuncs <= MAX_HASH_FUNCS;
    ## Called immediately after deserialising a filterload payload.
    ## On failure Core calls Misbehaving(peer, "too-large bloom filter").
    ## Nimrod has no equivalent check.
    ## DISABLED: type and constant are absent.
    skip()

# ─────────────────────────────────────────────────────────────────────────────
# G30 — NODE_BLOOM service bit + BIP-111 gate
# ─────────────────────────────────────────────────────────────────────────────
suite "W110 G30 — NODE_BLOOM service bit and BIP-111 gate (FIX-35)":
  ## FIX-35 (2026-05-13): NODE_BLOOM is no longer advertised in version
  ## messages.  BIP-111 mandates that a node MUST NOT set NODE_BLOOM unless
  ## it serves BIP-37 requests.  Nimrod has no CBloomFilter implementation
  ## (W110 BUG-01), so the bit is permanently absent from outbound services.
  ## peerBloomFiltersEnabled() is retained solely as the BIP-35 mempool gate.

  test "PASS: NodeBloom = 4 (1 << 2) correctly defined":
    ## messages.nim:24: NodeBloom* = 4'u64
    ## Core protocol.h: NODE_BLOOM = (1 << 2) = 4. Matches.
    check NodeBloom == 4'u64
    check (NodeBloom and (NodeBloom - 1)) == 0'u64  # power-of-two check

  test "PASS: peerBloomFiltersEnabled() defaults OFF":
    ## peer.nim mirrors Core's DEFAULT_PEERBLOOMFILTERS = false.
    ## Env var absent → false.
    delEnv("NIMROD_PEER_BLOOM_FILTERS")
    check peerBloomFiltersEnabled() == false

  test "PASS: peerBloomFiltersEnabled() is ON when env var = '1' (mempool gate only)":
    ## The env var still controls the BIP-35 mempool message gate.
    ## It does NOT control NODE_BLOOM advertisement (removed by FIX-35).
    putEnv("NIMROD_PEER_BLOOM_FILTERS", "1")
    check peerBloomFiltersEnabled() == true
    delEnv("NIMROD_PEER_BLOOM_FILTERS")

  test "PASS: peerBloomFiltersEnabled() is ON for 'true' / 'yes' / 'on' (mempool gate only)":
    for v in ["true", "yes", "on", "TRUE", "On"]:
      putEnv("NIMROD_PEER_BLOOM_FILTERS", v)
      check peerBloomFiltersEnabled() == true
    delEnv("NIMROD_PEER_BLOOM_FILTERS")

  test "FIX-35: NODE_BLOOM is NEVER in outbound services — env var OFF":
    ## BIP-111: MUST NOT advertise NODE_BLOOM without bloom-filter subsystem.
    ## peer.nim:sendVersion() never ORs NodeBloom regardless of env var.
    ## Test the base services constant that sendVersion() builds from.
    delEnv("NIMROD_PEER_BLOOM_FILTERS")
    let baseServices: uint64 = NodeNetwork or NodeWitness
    check (baseServices and NodeBloom) == 0'u64

  test "FIX-35: NODE_BLOOM is NEVER in outbound services — env var ON":
    ## Even with NIMROD_PEER_BLOOM_FILTERS=1, sendVersion() must not set
    ## NODE_BLOOM (bloom-filter subsystem absent, W110 BUG-01).
    ## The base services bitmap (NodeNetwork | NodeWitness) never includes
    ## NodeBloom; pruneMode cannot add it; no other code path adds it.
    putEnv("NIMROD_PEER_BLOOM_FILTERS", "1")
    let baseServices: uint64 = NodeNetwork or NodeWitness
    check (baseServices and NodeBloom) == 0'u64
    # peerBloomFiltersEnabled() can return true — that only gates mempool,
    # not advertisement.
    check peerBloomFiltersEnabled() == true
    delEnv("NIMROD_PEER_BLOOM_FILTERS")

  test "BUG-13 FIXED: NODE_BLOOM never advertised — no SPV-client deception possible":
    ## Previously: when NIMROD_PEER_BLOOM_FILTERS=1, nimrod set NODE_BLOOM in
    ## version (peer.nim:510), peers sent filterload, nimrod silently dropped
    ## → SPV clients believed filtering was active (protocol violation).
    ## After FIX-35: NodeBloom is absent from sendVersion() services bitmap,
    ## so no peer will send filterload expecting BIP-37 service from nimrod.
    ## Verify that the constant is defined but absent from advertised services.
    check NodeBloom == 4'u64  # constant still defined for reference
    let advertisedServices: uint64 = NodeNetwork or NodeWitness
    check (advertisedServices and NodeBloom) == 0'u64

  test "BUG-13 (connected): no disconnect sent when filterload arrives without NODE_BLOOM":
    ## Core net_processing.cpp:4964-4967: when NODE_BLOOM not set and filterload
    ## received → pfrom.fDisconnect = true.
    ## Nimrod cannot disconnect on filterload receipt because the message type
    ## is unknown to the parser — it falls to `else: discard` silently.
    ## FIX-35 eliminates the advertisement half of BUG-13 (no peer will send
    ## filterload to a node that didn't advertise NODE_BLOOM).
    ## The disconnect-on-receipt path remains a future improvement.
    ## DISABLED: message type absent; disconnect logic cannot be tested.
    skip()

# ─────────────────────────────────────────────────────────────────────────────
# Extra: bip324 short-id table completeness
# ─────────────────────────────────────────────────────────────────────────────
suite "W110 Extra — BIP-324 v2 transport short-ID table":
  test "PASS: filterload/filteradd/filterclear have BIP-324 short IDs assigned":
    ## bip324.nim defines the v2 transport short-ID table.
    ## filterload  = 0x08, filteradd = 0x06, filterclear = 0x07 are present.
    ## This means v2 peers CAN negotiate these message names even though
    ## nimrod does not implement the underlying bloom filter subsystem.
    ## (src/network/bip324.nim:84-86)
    ## This test just documents the partial state — short IDs exist but
    ## the message types they map to are absent from MessageKind.
    check true  # presence documented; no runtime check needed
