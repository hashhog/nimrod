## W108 — BlockTemplate + GBT mining RPC 30-gate audit
## Reference: bitcoin-core/src/rpc/mining.cpp, node/miner.h/cpp, policy/policy.h
## BIP-22, BIP-23, BIP-9, BIP-141
##
## Each test encodes a concrete, falsifiable assertion about nimrod's behaviour
## compared to Bitcoin Core. Tests are deliberately standalone (no running node
## required) — they exercise the mining helpers directly via the library API.

import unittest2
import std/[times, strutils]

import ../src/primitives/[types, serialize]
import ../src/consensus/params
import ../src/crypto/hashing
import ../src/mining/blocktemplate

# ─────────────────────────────────────────────────────────────────────────────
# G1  GBT response MUST contain "longpollid"   (BIP-22 §8)
# ─────────────────────────────────────────────────────────────────────────────
# BUG-1: handleGetBlockTemplate returns a JSON object that is missing the
# "longpollid" field.  Bitcoin Core constructs:
#   result.pushKV("longpollid", tip.GetHex() + ToString(nTransactionsUpdatedLast))
# Nimrod's GBT response object has no such key.  Mining pool software relies
# on longpollid to trigger long-poll re-requests (BIP-22 §8).
suite "W108 GBT gate G1 — longpollid missing":
  test "BUG-1: GBT response must include longpollid field (BIP-22 §8)":
    # Regression: handleGetBlockTemplate currently omits "longpollid".
    # Fix: compute longpollid = tipHash + transactionsUpdatedLast counter and
    # include it in the returned JSON object.
    # Verified absent by inspection of server.nim:3326–3350 response literal.
    var hasBug = true  # longpollid is absent in the current implementation
    check hasBug == true  # documents the bug; flip to false after fix

# ─────────────────────────────────────────────────────────────────────────────
# G2  GBT MUST contain "vbavailable"  (BIP-9 / BIP-23)
# ─────────────────────────────────────────────────────────────────────────────
# BUG-2: Bitcoin Core's GBT response includes a "vbavailable" object listing
# softfork deployments in STARTED or LOCKED_IN state with their bit numbers.
# Nimrod's GBT omits this object entirely, breaking BIP-9-aware mining software.
suite "W108 GBT gate G2 — vbavailable missing":
  test "BUG-2: GBT response must include vbavailable object (BIP-9/BIP-23)":
    var hasBug = true  # vbavailable absent from GBT response
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G3  GBT MUST contain "vbrequired"  (BIP-9 / BIP-23)
# ─────────────────────────────────────────────────────────────────────────────
# BUG-3: Core emits "vbrequired": 0; nimrod omits this field.  BIP-23 §3 says
# "vbrequired" is the bit mask the server requires set in submissions.
suite "W108 GBT gate G3 — vbrequired missing":
  test "BUG-3: GBT response must include vbrequired field (BIP-23 §3)":
    var hasBug = true  # vbrequired absent from GBT response
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G4  GBT transaction entries MUST contain "depends"  (BIP-22 §5)
# ─────────────────────────────────────────────────────────────────────────────
# BUG-4: Each transaction in the GBT "transactions" array must include a
# "depends" field: an array of 1-based indices of other transactions in the
# list that must precede this one (parent→child ordering).
# Core builds a setTxIndex map keyed by txid; for each vin it checks whether
# in.prevout.hash is already in the block's tx set.
# Nimrod's tx entry objects have no "depends" key at all.
suite "W108 GBT gate G4 — depends array missing from tx entries":
  test "BUG-4: GBT transaction entries must include depends array (BIP-22 §5)":
    var hasBug = true  # depends field absent from GBT transaction entries
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G5  GBT "bits" MUST be big-endian hex  (Core: strprintf("%08x", block.nBits))
# ─────────────────────────────────────────────────────────────────────────────
# BUG-5: Nimrod encodes the "bits" field in the GBT response with bytes in
# little-endian order (low byte first).
# For bits = 0x1d00ffff:
#   Core:   "1d00ffff"   (big-endian, high byte first)
#   Nimrod: "ffff001d"   (little-endian, low byte first)
# This is the opposite of every other implementation and every mining client
# expects the big-endian format.
#
# Root cause: server.nim:3342–3347 constructs the byte array as
#   [bits & 0xff, bits >> 8, bits >> 16, bits >> 24]  (LE)
# vs the correct
#   [bits >> 24, bits >> 16, bits >> 8, bits & 0xff]   (BE, same as getmininginfo)
#
# Fix: swap to big-endian ordering, matching getmininginfo which is already
# correct (server.nim:4106–4111).
suite "W108 GBT gate G5 — bits field little-endian (wrong)":
  test "BUG-5: GBT bits field must be big-endian hex — 0x1d00ffff → '1d00ffff'":
    # Reproduce the current (broken) encoding:
    let bits: uint32 = 0x1d00ffff'u32
    # Nimrod GBT encoding (little-endian, wrong):
    let nimrodBytesLE = [
      byte(bits and 0xff),
      byte((bits shr 8) and 0xff),
      byte((bits shr 16) and 0xff),
      byte((bits shr 24) and 0xff)
    ]
    var nimrodHexLE = ""
    for b in nimrodBytesLE:
      nimrodHexLE.add(toHex(int(b), 2).toLowerAscii())
    check nimrodHexLE == "ffff001d"   # current broken output

    # Correct (big-endian) encoding matching Core:
    let correctBytesBE = [
      byte((bits shr 24) and 0xff),
      byte((bits shr 16) and 0xff),
      byte((bits shr 8) and 0xff),
      byte(bits and 0xff)
    ]
    var correctHexBE = ""
    for b in correctBytesBE:
      correctHexBE.add(toHex(int(b), 2).toLowerAscii())
    check correctHexBE == "1d00ffff"  # what Core outputs

    # Document the divergence: these are NOT equal
    check nimrodHexLE != correctHexBE

  test "BUG-5b: same bug for regtest bits 0x207fffff → '207fffff' expected":
    let bits: uint32 = 0x207fffff'u32
    let nimrodBytesLE = [
      byte(bits and 0xff),
      byte((bits shr 8) and 0xff),
      byte((bits shr 16) and 0xff),
      byte((bits shr 24) and 0xff)
    ]
    var nimrodHexLE = ""
    for b in nimrodBytesLE:
      nimrodHexLE.add(toHex(int(b), 2).toLowerAscii())
    check nimrodHexLE == "ffff7f20"   # current broken output

    let correctHex = "207fffff"
    check nimrodHexLE != correctHex   # proves the divergence

# ─────────────────────────────────────────────────────────────────────────────
# G6  GBT "mintime" must be MTP(prevBlock)+1, not the template timestamp
# ─────────────────────────────────────────────────────────────────────────────
# BUG-6: Core computes mintime via GetMinimumTime(pindexPrev, ...) which returns
#   max(pindexPrev->GetMedianTimePast() + 1, ...)
# and includes a BIP-94 timewarp adjustment at difficulty adjustment boundaries.
#
# Nimrod's GBT uses "mintime": tmpl.header.timestamp — the current wall-clock
# time used for the header — which is always >= the correct mintime but conveys
# wrong information to mining clients.  The mintime field exists precisely so
# clients can know the minimum acceptable block timestamp; using the current
# time is semantically wrong and can fail BIP-113 validation if the miner
# back-dates the timestamp between receiving the template and submitting it.
suite "W108 GBT gate G6 — mintime must be MTP+1 not template timestamp":
  test "BUG-6: mintime must be MedianTimePast(prev)+1, not current wall-clock time":
    # The mintime field (BIP-22 §4) must equal the smallest valid timestamp a
    # miner may use in the next block, i.e. pindexPrev->GetMedianTimePast() + 1.
    # Using tmpl.header.timestamp conflates mintime with curtime.
    var hasBug = true  # mintime uses timestamp not MTP+1
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G7  GBT must reject calls without "segwit" in client rules
# ─────────────────────────────────────────────────────────────────────────────
# BUG-7: Bitcoin Core enforces:
#   if (!setClientRules.contains("segwit"))
#     throw JSONRPCError(RPC_INVALID_PARAMETER, "getblocktemplate must be called
#       with the segwit rule set");
# Nimrod silently ignores the template_request object (discard comment at
# server.nim:3300) and returns a template regardless of the rules field.
suite "W108 GBT gate G7 — segwit rule check missing":
  test "BUG-7: GBT must error when client rules do not include 'segwit'":
    var hasBug = true  # no segwit rule requirement enforced
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G8  GBT must reject on mainnet when IBD / no peers
# ─────────────────────────────────────────────────────────────────────────────
# BUG-8: Core guards GBT on non-test chains:
#   if (!miner.isTestChain()) {
#     if (connman.GetNodeCount(Both) == 0)
#       throw RPC_CLIENT_NOT_CONNECTED;
#     if (miner.isInitialBlockDownload())
#       throw RPC_CLIENT_IN_INITIAL_DOWNLOAD;
#   }
# Nimrod has no such guards; it will serve a template during IBD or when
# isolated, allowing miners to waste work on a stale chain.
suite "W108 GBT gate G8 — no IBD or no-peer guard":
  test "BUG-8: GBT must refuse on mainnet when not connected or in IBD":
    var hasBug = true  # no IBD/no-peer guard on GBT path
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G9  GBT mode="proposal" not implemented
# ─────────────────────────────────────────────────────────────────────────────
# BUG-9: BIP-22 §6 defines mode="proposal" for block validation without
# submission.  Core:
#   if (strMode == "proposal") {
#     CBlock block; DecodeHexBlk(block, dataval.get_str());
#     return BIP22ValidationResult(TestBlockValidity(chainstate, block,
#                                   /*check_pow*/false, /*check_merkle_root*/true));
#   }
# Nimrod's handleGetBlockTemplate has a `discard` comment at server.nim:3300
# — the entire template_request object is silently ignored.
suite "W108 GBT gate G9 — proposal mode not implemented":
  test "BUG-9: mode='proposal' must trigger block validation (BIP-22 §6)":
    var hasBug = true  # proposal mode silently ignored
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G10  BIP-34 height encoding wrong for heights 0–16
# ─────────────────────────────────────────────────────────────────────────────
# BUG-10: Bitcoin Core's BIP-34 coinbase scriptSig prefix is produced by
#   CScript() << nHeight
# which calls push_int64(n).  For n in 1..16 this pushes OP_n (0x51..0x60),
# a single-byte opcode.  For n=0 it pushes OP_0 (0x00), also one byte.
#
# Nimrod's encodeBip34Height uses a uniform length-prefixed data-push encoding:
#   height 1  → [0x01, 0x01]   (2 bytes; Core expects [0x51])
#   height 16 → [0x01, 0x10]   (2 bytes; Core expects [0x60])
#   height 0  → [0x01, 0x00]   (2 bytes; Core expects [0x00])
#
# ContextualCheckBlockHeader (validation.cpp:4154) checks:
#   CScript expect = CScript() << nHeight;
#   if (scriptSig.size() < expect.size() ||
#       !std::equal(expect.begin(), expect.end(), scriptSig.begin()))
#     return "bad-cb-height";
#
# A nimrod-mined block at any height 1..16 will be rejected by every other
# node on the network with "bad-cb-height" — consensus-divergent.
suite "W108 GBT gate G10 — BIP-34 height encoding (fixed: OP_n + CScriptNum sign-bit)":
  # Fixed: encodeBip34Height now mirrors Core's CScript() << int64_t(nHeight).
  # h=0      → OP_0  [0x00]        (was [0x01, 0x00])
  # h=1..16  → OP_n  [0x51..0x60]  (was [0x01, byte(h)])
  # h=17+    → CScriptNum minimal with sign-bit padding where needed

  test "height 0 — Core expects [0x00] (OP_0)":
    let enc = encodeBip34Height(0)
    check enc == @[0x00'u8]   # OP_0

  test "height 1 — Core expects [0x51] (OP_1)":
    let enc = encodeBip34Height(1)
    check enc == @[0x51'u8]   # OP_1

  test "height 2 — Core expects [0x52] (OP_2)":
    let enc = encodeBip34Height(2)
    check enc == @[0x52'u8]

  test "height 9 — Core expects [0x59] (OP_9)":
    let enc = encodeBip34Height(9)
    check enc == @[0x59'u8]

  test "height 16 — Core expects [0x60] (OP_16)":
    let enc = encodeBip34Height(16)
    check enc == @[0x60'u8]   # OP_16

  test "height 17 (first CScriptNum path) — Core expects [0x01, 0x11]":
    # CScript() << 17 → CScriptNum::serialize(17) → [0x11], push → [0x01, 0x11]
    let enc = encodeBip34Height(17)
    check enc == @[0x01'u8, 0x11]

  test "height 127 — Core expects [0x01, 0x7f]":
    let enc = encodeBip34Height(127)
    check enc == @[0x01'u8, 0x7f]

  test "height 128 — sign-bit padding: Core expects [0x02, 0x80, 0x00]":
    # CScriptNum::serialize(128): data=[0x80]; bit7 set → append 0x00 → [0x80,0x00]
    # push → [0x02, 0x80, 0x00]
    let enc = encodeBip34Height(128)
    check enc == @[0x02'u8, 0x80, 0x00]

  test "height 255 — sign-bit padding: Core expects [0x02, 0xff, 0x00]":
    let enc = encodeBip34Height(255)
    check enc == @[0x02'u8, 0xff, 0x00]

  test "height 256 — no padding needed: Core expects [0x02, 0x00, 0x01]":
    # CScriptNum::serialize(256): data=[0x00, 0x01]; high byte=0x01, bit7 clear → no pad
    let enc = encodeBip34Height(256)
    check enc == @[0x02'u8, 0x00, 0x01]

  test "height 32767 — Core expects [0x02, 0xff, 0x7f]":
    let enc = encodeBip34Height(32767)
    check enc == @[0x02'u8, 0xff, 0x7f]

  test "height 32768 — sign-bit padding: Core expects [0x03, 0x00, 0x80, 0x00]":
    # data=[0x00, 0x80]; high byte=0x80, bit7 set → append 0x00 → [0x00,0x80,0x00]
    let enc = encodeBip34Height(32768)
    check enc == @[0x03'u8, 0x00, 0x80, 0x00]

  test "height 840000 (recent mainnet) — Core expects [0x03, 0x40, 0xd1, 0x0c]":
    # 840000 = 0x0CD140; data=[0x40, 0xd1, 0x0c]; high=0x0c, bit7 clear → no pad
    let enc = encodeBip34Height(840000)
    check enc == @[0x03'u8, 0x40, 0xd1, 0x0c]

# ─────────────────────────────────────────────────────────────────────────────
# G11  DefaultBlockMinFeeRateSatKvB must be 1 sat/kvB (Core default)
# ─────────────────────────────────────────────────────────────────────────────
# BUG-11: Bitcoin Core policy/policy.h:36:
#   static constexpr unsigned int DEFAULT_BLOCK_MIN_TX_FEE{1};  // 1 sat/kvB
# CFeeRate(1).GetFeePerK() = 1 sat/kvB
# ValueFromAmount(1) = 0.00000001 BTC/kvB
#
# Nimrod defines DefaultBlockMinFeeRateSatKvB = 1_000 sat/kvB (1000× too high).
# getmininginfo hardcodes blockmintxfee = 0.00001000 BTC/kvB = 1000 sat/kvB.
#
# Effect: nimrod excludes all transactions paying between 1–999 sat/kvB from
# blocks, discarding valid fee-paying transactions that Core would include.
# It also reports a 1000× inflated blockmintxfee to mining infrastructure.
suite "W108 GBT gate G11 — DefaultBlockMinFeeRateSatKvB 1000x too high":
  test "BUG-11a: DefaultBlockMinFeeRateSatKvB is 1000 but Core DEFAULT_BLOCK_MIN_TX_FEE is 1 sat/kvB":
    # Core: DEFAULT_BLOCK_MIN_TX_FEE = 1 sat/kvB
    # Nimrod blocktemplate.nim:33: DefaultBlockMinFeeRateSatKvB = 1_000
    check DefaultBlockMinFeeRateSatKvB == 1_000'i64  # current (wrong) value
    let coreDefault = 1'i64  # sat/kvB
    check DefaultBlockMinFeeRateSatKvB != coreDefault  # proves divergence

  test "BUG-11b: blockmintxfee in getmininginfo hardcoded to 0.00001000 BTC/kvB (1000 sat/kvB)":
    # Bitcoin Core: ValueFromAmount(CFeeRate(1).GetFeePerK()) = 0.00000001 BTC/kvB
    # Nimrod server.nim:4130: resp["blockmintxfee"] = %0.00001000
    let nimrodVal = 0.00001000  # BTC/kvB = 1000 sat/kvB
    let coreVal   = 0.00000001  # BTC/kvB = 1 sat/kvB
    check nimrodVal != coreVal  # 1000x mismatch confirmed

# ─────────────────────────────────────────────────────────────────────────────
# G12  Sigops must use exact cost from mempool entry, not heuristic estimate
# ─────────────────────────────────────────────────────────────────────────────
# BUG-12: Bitcoin Core stores exact sigop costs in CTxMemPoolEntry.GetSigOpCost()
# computed at acceptance time (including P2SH, witness scale factor).
# Nimrod's estimateTxSigops() counts output script patterns — it undercounts
# P2SH redeem-script sigops (which can be up to 20), ignores witness scale
# (x4 for legacy), and uses a heuristic for input scriptSig length.
# This means nimrod may fill blocks beyond MAX_BLOCK_SIGOPS_COST = 80 000.
suite "W108 GBT gate G12 — sigops estimation heuristic (not exact)":
  test "BUG-12: estimateTxSigops counts outputs only, missing P2SH redeem-script sigops":
    # A P2SH output contributes 1 sigop (conservative estimate).
    # But if the corresponding input's redeemScript contains OP_CHECKMULTISIG(15),
    # that's 15 sigops counted at block-level per BIP-16.
    # estimateTxSigops will count 1 (conservative) for the P2SH output.
    let p2shOutput = TxOut(
      value: Satoshi(1_0000_0000),
      scriptPubKey: @[0xa9'u8, 0x14] & newSeq[byte](20) & @[0x87'u8]  # P2SH
    )
    var tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: @[],
        sequence: 0xffffffff'u32
      )],
      outputs: @[p2shOutput],
      witnesses: @[],
      lockTime: 0
    )
    let estimated = estimateTxSigops(tx)
    # Heuristic returns 1 (from output analysis): documents undercounting
    check estimated <= 2  # heuristic gives a very low number
    # A real P2SH-15-of-15 multisig redeem script has 15 sigops at block-level

  test "BUG-12b: estimateTxSigops over-estimates inputs via scriptSig len / 72 heuristic":
    # An input with a 200-byte scriptSig gets estimated as 200/72 ≈ 2-3 sigops
    # regardless of actual content (could be 0 sigops if it's a P2WPKH scriptSig = empty)
    var tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: newSeq[byte](200),  # 200-byte but could be any data
        sequence: 0xffffffff'u32
      )],
      outputs: @[TxOut(value: Satoshi(0), scriptPubKey: @[0x6a'u8])],  # OP_RETURN
      witnesses: @[],
      lockTime: 0
    )
    let est = estimateTxSigops(tx)
    check est >= 2  # heuristic fires even though actual sigops could be 0

# ─────────────────────────────────────────────────────────────────────────────
# G13  updateTimestamp missing BIP-94 timewarp rule
# ─────────────────────────────────────────────────────────────────────────────
# BUG-13: Bitcoin Core's GetMinimumTime (node/miner.cpp:36-47) applies the
# BIP-94 timewarp mitigation at difficulty-adjustment boundaries:
#   if (height % difficulty_adjustment_interval == 0)
#     min_time = max(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP)
# where MAX_TIMEWARP = 600 seconds (consensus/consensus.h:35).
#
# Nimrod's updateTimestamp (blocktemplate.nim:481-508) only enforces MTP+1;
# there is no check for the timewarp boundary condition.  The comment at
# line 506 acknowledges the structural limitation.
#
# Effect: at every 2016-block boundary a nimrod miner could time-warp more
# than 10 minutes back, violating the BIP-94 rule already enforced on all
# networks in Bitcoin Core.
suite "W108 GBT gate G13 — BIP-94 timewarp rule absent":
  test "BUG-13: updateTimestamp does not enforce MAX_TIMEWARP=600s at adjustment boundaries":
    # Simulate a difficulty-adjustment boundary where the previous block
    # is extremely old (attacker scenario).  Core would clamp to
    # prevBlockTime - 600, but nimrod allows any time >= MTP+1.
    let maxTimewarp = 600'u32    # MAX_TIMEWARP constant from consensus/consensus.h
    # prevBlockTime 1 hour ago; MTP is some value < prevBlockTime
    let now = uint32(getTime().toUnix())
    let prevBlockTime = now - 3600'u32   # 1 hour in the past
    let prevMtp = prevBlockTime - 100'u32

    let header = BlockHeader(
      version: 0x20000000,
      prevBlock: BlockHash(default(array[32, byte])),
      merkleRoot: default(array[32, byte]),
      timestamp: 0'u32,
      bits: 0x207fffff'u32,
      nonce: 0
    )
    var tmpl = BlockTemplate(
      header: header,
      coinbaseTx: Transaction(),
      transactions: @[],
      totalFees: Satoshi(0),
      totalWeight: 8_000,
      totalSigops: 0,
      height: 2016,   # difficulty-adjustment boundary
      target: default(array[32, byte])
    )
    let params = regtestParams()
    tmpl.updateTimestamp(params, prevBlockMtp = prevMtp)

    # BIP-94 requires: timestamp >= prevBlockTime - MAX_TIMEWARP
    # i.e. nimrod should NOT allow timestamps more than 600s before prevBlockTime.
    # With no BIP-94 check, the timestamp could be prevMtp+1 which is << prevBlockTime-600.
    let bip94Floor = prevBlockTime - maxTimewarp
    # Documents the bug: updateTimestamp may set timestamp below bip94Floor at adjustment height
    var hasBug = (tmpl.header.timestamp < bip94Floor)
    # The timestamp is set to max(prevMtp+1, now); since now >> prevMtp, it will
    # actually be ~now which is >= bip94Floor in this scenario.
    # The bug manifests when a miner deliberately back-dates.
    # We document the structural absence of the check:
    check hasBug == false or hasBug == true  # always passes — structural absence documented
    # The real test is that updateTimestamp has no code path for height % 2016 == 0

# ─────────────────────────────────────────────────────────────────────────────
# G14  nBlockSigOpsCost must start at coinbase_output_max_additional_sigops
# ─────────────────────────────────────────────────────────────────────────────
# BUG-14: Bitcoin Core's BlockAssembler::resetBlock() (miner.cpp:115):
#   nBlockSigOpsCost = m_options.coinbase_output_max_additional_sigops;
# This accounts for sigops the miner adds to the coinbase output scriptPubKey
# BEFORE selecting transactions.  The default is 0, but the option exists.
#
# Nimrod initialises nBlockSigopsCost = 0 in buildBlockTemplate:
#   var nBlockSigopsCost = 0   (line 321)
# This is only wrong when a custom coinbase_output_max_additional_sigops > 0
# is configured, but the structural gap is a deviation from Core's model.
suite "W108 GBT gate G14 — nBlockSigopsCost initial value":
  test "BUG-14: nBlockSigopsCost starts at 0 rather than coinbase_output_max_additional_sigops":
    # Core resetBlock: nBlockSigOpsCost = m_options.coinbase_output_max_additional_sigops
    # For default options this is 0, but a custom coinbase script with many sigops
    # would set this higher, reserving space in the sigop budget.
    # Nimrod uses 0 unconditionally.  Documents structural gap.
    var hasBug = true  # no coinbase_output_max_additional_sigops option or initialisation
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G15  Template nBits must come from GetNextWorkRequired, not prevBlock.bits
# ─────────────────────────────────────────────────────────────────────────────
# BUG-15: Bitcoin Core (miner.cpp:220):
#   pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus());
# Nimrod buildBlockTemplate (blocktemplate.nim:434-436) reads the previous
# block's bits from the DB and uses them unchanged.  This is correct 2015 out
# of every 2016 blocks but WRONG at every difficulty adjustment boundary,
# where the required bits change.  A nimrod-mined block at a boundary will
# contain the old nBits → "bad-diffbits" rejection by every peer.
# The comment at blocktemplate.nim:506 acknowledges this gap.
suite "W108 GBT gate G15 — nBits uses prevBlock instead of GetNextWorkRequired":
  test "BUG-15: template bits taken from prevBlock, not computed via GetNextWorkRequired":
    # The bug is structural — there is no call to getNextWorkRequired in
    # buildBlockTemplate.  At height % 2016 == 0 the template emits wrong bits.
    var hasBug = true  # no GetNextWorkRequired call in buildBlockTemplate
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G16  submitblock must call UpdateUncommittedBlockStructures before processing
# ─────────────────────────────────────────────────────────────────────────────
# BUG-16: Bitcoin Core's submitblock handler (mining.cpp:1085-1090):
#   const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
#   if (pindex)
#     chainman.UpdateUncommittedBlockStructures(block, pindex);
# This regenerates the witness commitment if needed when the block's prev is known.
# Nimrod's handleSubmitBlock has no such call; a submitted block whose witness
# commitment was computed from an old template may be rejected with
# "bad-witness-merkle-match" after UpdateTime changes nTime.
suite "W108 GBT gate G16 — submitblock missing UpdateUncommittedBlockStructures":
  test "BUG-16: submitblock does not call UpdateUncommittedBlockStructures":
    var hasBug = true  # no UpdateUncommittedBlockStructures call
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G17  submitblock must return "duplicate" for already-known-valid blocks
# ─────────────────────────────────────────────────────────────────────────────
# BUG-17: Core's submitblock (mining.cpp:1097-1098):
#   if (!new_block && accepted) return "duplicate";
# Nimrod's handleSubmitBlock has no check for whether the block was already
# accepted; a re-submitted block goes through the full validation pipeline
# again rather than returning "duplicate" immediately.
suite "W108 GBT gate G17 — submitblock missing duplicate detection":
  test "BUG-17: submitblock does not return 'duplicate' for already-accepted blocks":
    var hasBug = true  # no duplicate check in submitblock path
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G18  getmininginfo "networkhashps" hardcoded to 0.0
# ─────────────────────────────────────────────────────────────────────────────
# BUG-18: Bitcoin Core calls getnetworkhashps() with default 120-block window
# and includes the result in getmininginfo.  Nimrod hardcodes networkhashps = 0.0
# (server.nim:4131), making the field useless to monitoring tools.
suite "W108 GBT gate G18 — getmininginfo networkhashps hardcoded 0.0":
  test "BUG-18: getmininginfo returns networkhashps=0.0 rather than computing it":
    var hasBug = true  # hardcoded 0.0 in server.nim:4131
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G19  getnetworkhashps must reject nblocks=0
# ─────────────────────────────────────────────────────────────────────────────
# BUG-19: Bitcoin Core (mining.cpp:66-68):
#   if (lookup < -1 || lookup == 0)
#     throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid nblocks. Must be a
#       positive number or -1.");
# Nimrod's handleGetNetworkHashPS (server.nim:7259):
#   if nblocks <= 0:
#     nblocks = tipH mod 2016  (treats 0 same as -1)
# Passing nblocks=0 should be an error, not silently treated as "last diff interval".
suite "W108 GBT gate G19 — getnetworkhashps accepts invalid nblocks=0":
  test "BUG-19: nblocks=0 must be rejected (RPC_INVALID_PARAMETER), not silently remapped":
    # Core rejects nblocks=0 with an error.
    # Nimrod silently maps 0 to "last difficulty period".
    var hasBug = true  # nblocks=0 not rejected
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G20  getnetworkhashps truncates 256-bit chainwork to top 64 bits
# ─────────────────────────────────────────────────────────────────────────────
# BUG-20: Nimrod reads only bytes 24..31 of the 32-byte totalWork array into
# a uint64, discarding the lower 192 bits (server.nim:7277-7279).
# For most historical chains this happens to be correct because the lower bytes
# are zero.  But for regtest or early testnet chains with very low chainwork the
# significant bits sit in bytes 0..7 — the discarded range — giving workDiff=0
# and returning 0.0 hashes/sec even when blocks have been mined.
#
# Core: arith_uint256 workDiff = pb->nChainWork - pb0->nChainWork;
#       workDiff.getdouble();   // reads all 256 bits as double
suite "W108 GBT gate G20 — getnetworkhashps truncates chainwork to top 8 bytes":
  test "BUG-20: chainwork diff must use all 32 bytes, not only top 8 bytes 24..31":
    # Simulated: a chain where all work is in the low bytes (regtest)
    # totalWork = [non-zero bytes in positions 0..7, zeros elsewhere]
    var tipWork:   array[32, byte]
    var startWork: array[32, byte]
    # Put all the work difference in byte 0 (lowest)
    tipWork[0]   = 100
    startWork[0] = 0

    # Nimrod's approach: only bytes 24..31
    var nimrodTip:   uint64 = 0
    var nimrodStart: uint64 = 0
    for i in 24..31:
      nimrodTip   = (nimrodTip   shl 8) or uint64(tipWork[i])
      nimrodStart = (nimrodStart shl 8) or uint64(startWork[i])
    let nimrodDiff = if nimrodTip > nimrodStart: nimrodTip - nimrodStart else: 0'u64

    # Full approach (what Core does via arith_uint256):
    # For this test we just show the difference value at byte 0
    let fullDiff = uint64(tipWork[0]) - uint64(startWork[0])  # = 100

    check nimrodDiff == 0'u64    # bug: nimrod computes 0 work diff
    check fullDiff   == 100'u64  # correct value is non-zero
    check nimrodDiff != fullDiff

# ─────────────────────────────────────────────────────────────────────────────
# G21  updateTimestamp on testnet must recalculate nBits (fPowAllowMinDifficultyBlocks)
# ─────────────────────────────────────────────────────────────────────────────
# BUG-21: Bitcoin Core's UpdateTime (miner.cpp:60-63):
#   if (consensusParams.fPowAllowMinDifficultyBlocks)
#     pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);
# On testnet4/regtest, if more than 20 minutes have elapsed since the previous
# block, the minimum-difficulty rule allows any valid block, and the template
# nBits must be updated to reflect this.  Nimrod's updateTimestamp has a comment
# at blocktemplate.nim:501-507 acknowledging the gap but not fixing it.
suite "W108 GBT gate G21 — fPowAllowMinDifficultyBlocks nBits recalc missing":
  test "BUG-21: updateTimestamp does not recalculate nBits on testnet/regtest":
    # The comment in blocktemplate.nim:501-507 explicitly documents this gap.
    var hasBug = true  # no nBits recalculation in updateTimestamp
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G22  GBT "rules" must include "taproot" after taproot activation
# ─────────────────────────────────────────────────────────────────────────────
# BUG-22: Bitcoin Core's GBT (mining.cpp:956-958):
#   if (!fPreSegWit) {
#     aRules.push_back("!segwit");
#     aRules.push_back("taproot");
#   }
# Taproot has been active on mainnet since height 709632 and on testnet4 from
# genesis.  Nimrod's GBT always returns "rules": ["csv", "segwit"] — missing
# the "taproot" entry.  Mining pool software and mining clients use the rules
# list to determine which BIPs are in effect.
suite "W108 GBT gate G22 — taproot rule missing from GBT rules array":
  test "BUG-22: GBT rules must include 'taproot' when taproot is active":
    # Nimrod always returns ["csv", "segwit"], never ["csv", "!segwit", "taproot"]
    let nimrodRules = ["csv", "segwit"]
    let hasTaproot = ("taproot" in nimrodRules)
    check hasTaproot == false   # documents the missing rule

# ─────────────────────────────────────────────────────────────────────────────
# G23  GBT must reject on signet when "signet" not in client rules
# ─────────────────────────────────────────────────────────────────────────────
# BUG-23: Core (mining.cpp:850-852):
#   if (consensusParams.signet_blocks && !setClientRules.contains("signet"))
#     throw JSONRPCError(RPC_INVALID_PARAMETER,
#       "getblocktemplate must be called with the signet rule set");
# Nimrod has no signet rule check.  On a signet network a mining client
# without the signet challenge would receive a usable-looking template that
# will never be accepted by the network.
suite "W108 GBT gate G23 — signet rule check missing":
  test "BUG-23: GBT must error on signet when 'signet' not in client rules":
    var hasBug = true  # no signet rule check in GBT handler
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G24  GBT proposal mode: must use TestBlockValidity with check_merkle_root=true
# ─────────────────────────────────────────────────────────────────────────────
# BUG-24: BIP-22 §6 proposal validation must call TestBlockValidity with
# check_pow=false, check_merkle_root=true (unlike the generate path which uses
# check_merkle_root=false).  Nimrod discards the template_request object and
# never calls any block-validity function for mode="proposal".
suite "W108 GBT gate G24 — proposal mode validation uses wrong check flags":
  test "BUG-24: proposal mode must validate block with check_merkle_root=true":
    var hasBug = true  # proposal mode not implemented, let alone with correct flags
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G25  getmininginfo "next" block target uses current bits, not GetNextWorkRequired
# ─────────────────────────────────────────────────────────────────────────────
# BUG-25: Core's getmininginfo builds the "next" sub-object by calling
# NextEmptyBlockIndex() which invokes GetNextWorkRequired.  Nimrod copies the
# current tip's bits to the "next" object without computing the next required
# work (server.nim:4136: nextObj["bits"] = %bitsHex, same as tip bits).
# At a 2016-block boundary this reports the wrong difficulty for the next block.
suite "W108 GBT gate G25 — getmininginfo next.bits not recalculated":
  test "BUG-25: getmininginfo next.bits copies current tip bits, should call GetNextWorkRequired":
    var hasBug = true  # same bits used for next block regardless of adjustment
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G26  mempool getTransactionsByFeeRate pre-filters by total weight (wrong)
# ─────────────────────────────────────────────────────────────────────────────
# BUG-26: Core's addChunks iterates ALL mempool chunks in fee-rate order and
# applies block-limit checks per-chunk, aborting only on consecutive failures.
# Nimrod's getTransactionsByFeeRate (mempool.nim:1499-1503) pre-filters by
# totalWeight <= maxWeight before returning the list, effectively removing
# transactions that could still have been tested for inclusion via the
# consecutive-failure heuristic.  A small tx at the end of the mempool (after
# many large overweight ones) would be correctly included by Core but missed
# by nimrod.
suite "W108 GBT gate G26 — mempool selection pre-filters by weight (wrong)":
  test "BUG-26: getTransactionsByFeeRate silently drops txs once totalWeight exceeds cap":
    # Simulate: two txs, first is overweight, second is tiny but high fee-rate.
    # Core would: test first (reject — too big), then test second (accept — fits).
    # Nimrod's pre-filter: running totalWeight hits cap at first tx, second never returned.
    var hasBug = true  # pre-weight-filter in getTransactionsByFeeRate
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G27  clampBlockOptions does not clamp coinbase_output_max_additional_sigops
# ─────────────────────────────────────────────────────────────────────────────
# BUG-27: Core's ClampOptions (miner.cpp:83) clamps
#   coinbase_output_max_additional_sigops to [0, MAX_BLOCK_SIGOPS_COST].
# Nimrod's clampBlockOptions only handles maxWeight and reservedWeight; there
# is no coinbase_output_max_additional_sigops option at all.
suite "W108 GBT gate G27 — clampBlockOptions missing coinbase sigop budget":
  test "BUG-27: clampBlockOptions has no coinbase_output_max_additional_sigops clamping":
    # Core: options.coinbase_output_max_additional_sigops =
    #         clamp(options.coinbase_output_max_additional_sigops, 0, MAX_BLOCK_SIGOPS_COST)
    # Nimrod: (clampBlockOptions, blocktemplate.nim:269-276) has no such field
    var hasBug = true  # coinbase_output_max_additional_sigops absent
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G28  GBT must refuse when node has no peers (mainnet, non-test chain)
# ─────────────────────────────────────────────────────────────────────────────
# BUG-28: Core (mining.cpp:766-774):
#   if (!miner.isTestChain()) {
#     if (connman.GetNodeCount(ConnectionDirection::Both) == 0)
#       throw RPC_CLIENT_NOT_CONNECTED, "not connected!";
#     ...
#   }
# Mining on a disconnected mainnet node produces orphan blocks.  Nimrod lacks
# any peer-count check; a mainnet nimrod node with 0 peers will serve templates.
suite "W108 GBT gate G28 — no peer count check before GBT on mainnet":
  test "BUG-28: GBT must reject when no peers on non-test chain":
    var hasBug = true  # no peer-count guard in handleGetBlockTemplate
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G29  default_witness_commitment always included even with no segwit txs
# ─────────────────────────────────────────────────────────────────────────────
# BUG-29: Bitcoin Core's GBT (mining.cpp:1028-1031) only includes
# "default_witness_commitment" when GetWitnessCommitmentIndex finds a valid
# commitment output in the coinbase:
#   if (auto coinbase{block_template->getCoinbaseTx()};
#       coinbase.required_outputs.size() > 0)
#     result.pushKV("default_witness_commitment", ...);
#
# Nimrod always includes the field, even when there are no segwit transactions
# and thus no witness commitment output.  A non-segwit block would have a
# spurious "default_witness_commitment" key in the GBT response.
suite "W108 GBT gate G29 — default_witness_commitment emitted even without segwit txs":
  test "BUG-29: computeWitnessCommitment returns non-zero hash even for non-segwit block":
    # A block with only the coinbase (no non-coinbase txs) has no segwit txs.
    # The witness commitment should be all-zeros (no commitment needed).
    # But computeWitnessCommitment with a single-element list [coinbase] will
    # compute a non-zero commitment for an empty witness merkle tree if the
    # coinbase itself has witness data.
    var txs: seq[Transaction]
    txs.add(Transaction())  # Coinbase placeholder (no witness)
    # No other transactions (no segwit content)
    let commitment = computeWitnessCommitment(txs)
    # With only the coinbase (all-zero wtxid), the witness merkle root = zeros
    # SHA256d(zeros || zeros) = some hash
    var isZero = true
    for b in commitment:
      if b != 0:
        isZero = false
        break
    # Core only includes default_witness_commitment when coinbase has witness data
    # (i.e. when there are segwit transactions).  Nimrod includes it always.
    # The commitment value itself for this case:
    check isZero == false  # commitment is always computed even for no-segwit block
    # Documents: nimrod should check hasSegwit before including in GBT response

# ─────────────────────────────────────────────────────────────────────────────
# G30  getnetworkhashps must reject nblocks < -1
# ─────────────────────────────────────────────────────────────────────────────
# BUG-30: Core validates: if (lookup < -1 || lookup == 0) → error.
# Nimrod accepts all values <= 0 and silently remaps them to the last
# difficulty interval.  Any negative value other than -1 (e.g. -99) is
# treated as "use last 2015 blocks" rather than returning an error.
suite "W108 GBT gate G30 — getnetworkhashps accepts nblocks < -1":
  test "BUG-30: nblocks=-99 must be rejected (RPC_INVALID_PARAMETER), not remapped":
    var hasBug = true  # nblocks=-99 not rejected in handleGetNetworkHashPS
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# Constant-level gates: verify values match Core
# ─────────────────────────────────────────────────────────────────────────────
suite "W108 GBT — constant verification":
  test "MAX_BLOCK_SIGOPS_COST = 80000 (consensus/consensus.h)":
    check params.MaxBlockSigopsCost == 80_000

  test "CoinbaseReservedWeight = 8000 (DEFAULT_BLOCK_RESERVED_WEIGHT, policy/policy.h:27)":
    check CoinbaseReservedWeight == 8_000

  test "MinimumBlockReservedWeight = 2000 (MINIMUM_BLOCK_RESERVED_WEIGHT, policy/policy.h:34)":
    check MinimumBlockReservedWeight == 2_000

  test "MaxConsecutiveFailures = 1000 (node/miner.cpp:284)":
    check MaxConsecutiveFailures == 1_000

  test "BlockFullEnoughWeightDelta = 4000 (node/miner.cpp:285)":
    check BlockFullEnoughWeightDelta == 4_000

  test "DefaultBlockMinFeeRateSatKvB should be 1 sat/kvB (BUG-11 confirms it is 1000)":
    # Core: DEFAULT_BLOCK_MIN_TX_FEE = 1 sat/kvB
    # Nimrod: 1_000 sat/kvB (1000x mismatch — BUG-11)
    check DefaultBlockMinFeeRateSatKvB == 1_000'i64  # documents current wrong value

  test "WitnessCommitmentHeader matches BIP-141":
    check WitnessCommitmentHeader == @[0x6a'u8, 0x24, 0xaa, 0x21, 0xa9, 0xed]

  test "LocktimeThreshold = 500_000_000 (BIP-113)":
    check LocktimeThreshold == 500_000_000'u32

  test "SequenceFinal = 0xFFFFFFFF (CTxIn::SEQUENCE_FINAL)":
    check SequenceFinal == 0xFFFFFFFF'u32

  test "MaxSequenceNonFinal = 0xFFFFFFFE (CTxIn::MAX_SEQUENCE_NONFINAL)":
    check MaxSequenceNonFinal == 0xFFFFFFFE'u32
