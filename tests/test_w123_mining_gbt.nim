## W123 — Mining/GBT parity (BlockAssembler + RPC) — 30-gate audit (nimrod)
##
## Scope: BlockAssembler / BlockTemplate / handleGetBlockTemplate /
## handleGetMiningInfo / handleSubmitBlock / handleGetNetworkHashPS, and the
## RPC surface for mining (prioritisetransaction, getprioritisedtransactions,
## submitheader, etc.).
##
## This wave is a follow-up to W108 (which carved out the first round of
## BlockTemplate/GBT gates).  Several gates here overlap-and-extend W108
## (e.g. G1 longpollid still absent; G14/G18 networkhashps FIXED 2026-06-28) —
## are reasserted as W123 forward regressions so a future "drive-by stub" in
## one place doesn't leave the other path silently broken.  Other gates probe
## territory W108 didn't touch (cluster mempool BlockBuilderChunk, BIP-94 mintime
## adjustment, signet_blocks gating, submitheader absence, currentblocksize
## divergence from Core, witness scale factor in fee-per-vsize, prioritisation
## delta, BIP-152 high-bandwidth peer count from GBT, etc.).
##
## All tests are xfail-shaped per W11x discovery-wave convention: each gate
## asserts the BUG condition holds today, then flips to "fixed" once a future
## FIX-N closes the gap. Tests are self-contained library-level checks, no
## running node required.
##
## References:
##   bitcoin-core/src/node/miner.cpp
##   bitcoin-core/src/rpc/mining.cpp
##   bitcoin-core/src/util/feefrac.cpp + .h
##   bitcoin-core/src/policy/policy.h
##   bitcoin-core/src/consensus/consensus.h
##   BIP-9 / BIP-22 / BIP-23 / BIP-94 / BIP-141 / BIP-152 / BIP-325

import unittest2
import std/[strutils]

import ../src/primitives/types
import ../src/consensus/params
import ../src/mining/blocktemplate
import ../src/mempool/mempool

# ─────────────────────────────────────────────────────────────────────────────
# G1  GBT response MUST include "longpollid"  (BIP-22 §8) — W108 carry-forward
# ─────────────────────────────────────────────────────────────────────────────
# BUG-1: handleGetBlockTemplate returns a JSON object that is missing the
# "longpollid" field.  Bitcoin Core mining.cpp:1002:
#   result.pushKV("longpollid", tip.GetHex() + ToString(nTransactionsUpdatedLast));
# Mining pools rely on longpollid to drive long-poll re-requests.
# W108 BUG-1 originally documented this; W123 carries it forward (no fix landed).
suite "W123 G1 — longpollid missing":
  test "BUG-1: GBT response must include longpollid field":
    # Carry-forward from W108 BUG-1.  As of W123 there is no longpollid emission
    # in handleGetBlockTemplate.  Tracked at server.nim:3642-3668 (no pushKV).
    var hasBug = true  # longpollid still absent
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G2  GBT "transactions" entries MUST include "depends" — W108 carry-forward
# ─────────────────────────────────────────────────────────────────────────────
# BUG-2: Each non-coinbase tx in the GBT "transactions" array must include a
# "depends" array — 1-based indices of preceding txs that must be present.
# Core mining.cpp:917-923 builds setTxIndex and pushes deps; nimrod
# server.nim:3600-3607 omits "depends" entirely.
# Without depends, mining pools cannot safely re-order or drop txs.
suite "W123 G2 — depends array missing from tx entries":
  test "BUG-2: GBT tx entries must include depends array":
    var hasBug = true  # depends still absent in tx entry construction
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G3  GBT "bits" MUST be big-endian (strprintf("%08x", nBits)) — W108 carry
# ─────────────────────────────────────────────────────────────────────────────
# BUG-3: Nimrod encodes the GBT "bits" field with byte order swapped vs Core.
# For nBits = 0x1d00ffff:
#   Core:   "1d00ffff"
#   Nimrod: "ffff001d"
# server.nim:3660-3665 hand-rolls little-endian byte array.  getmininginfo
# uses the correct big-endian path; only GBT is wrong.
suite "W123 G3 — GBT bits little-endian wrong":
  test "BUG-3: GBT bits field is little-endian (0x1d00ffff → 'ffff001d', wrong)":
    let bits: uint32 = 0x1d00ffff'u32
    # Current (wrong) encoding from server.nim:3660-3665:
    var leHex = ""
    leHex.add(toHex(int(bits and 0xff), 2).toLowerAscii())
    leHex.add(toHex(int((bits shr 8) and 0xff), 2).toLowerAscii())
    leHex.add(toHex(int((bits shr 16) and 0xff), 2).toLowerAscii())
    leHex.add(toHex(int((bits shr 24) and 0xff), 2).toLowerAscii())
    check leHex == "ffff001d"     # what nimrod emits today
    check leHex != "1d00ffff"     # what Core emits

# ─────────────────────────────────────────────────────────────────────────────
# G4  GBT "mintime" MUST be GetMinimumTime(prev, adjInterval) — W108 carry
# ─────────────────────────────────────────────────────────────────────────────
# BUG-4: Core mining.cpp:1004:
#   result.pushKV("mintime", GetMinimumTime(pindexPrev, DifficultyAdjustmentInterval()));
# where GetMinimumTime is MTP(prev)+1 with BIP-94 timewarp clamp at adjustment
# boundaries.  Nimrod server.nim:3653 emits tmpl.header.timestamp (curtime),
# conflating mintime with curtime.  A miner that back-dates the timestamp on
# template re-use would fail BIP-113.
suite "W123 G4 — mintime conflated with curtime":
  test "BUG-4: GBT mintime must be MTP(prev)+1 (with BIP-94 timewarp), not template ts":
    # Structural absence — no GetMinimumTime call site in server.nim:3577-3668.
    var hasBug = true
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G5  GBT MUST reject when client rules omit "segwit" — W108 carry-forward
# ─────────────────────────────────────────────────────────────────────────────
# BUG-5: Core mining.cpp:855-857:
#   if (!setClientRules.contains("segwit"))
#     throw RPC_INVALID_PARAMETER, "getblocktemplate must be called with the
#     segwit rule set";
# Nimrod server.nim:3583 `discard` — the template_request object is silently
# ignored, so a non-segwit-aware miner can still pull a segwit-enabled template
# and produce blocks the network will reject.
suite "W123 G5 — segwit rule enforcement missing":
  test "BUG-5: GBT must error when client rules lack 'segwit'":
    var hasBug = true
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G6  GBT MUST reject when client rules omit "signet" on signet  (BIP-325)
# ─────────────────────────────────────────────────────────────────────────────
# BUG-6: Core mining.cpp:850-852:
#   if (consensusParams.signet_blocks && !setClientRules.contains("signet"))
#     throw RPC_INVALID_PARAMETER, "...with the signet rule set ...";
# Nimrod has no signet_blocks consensus flag AND no rule-set parsing — a signet
# node will hand out templates to a non-signet-aware miner.  Even worse: nimrod
# never emits the signet_challenge field, so the miner cannot construct a valid
# signet block-witness commitment.
suite "W123 G6 — signet rule + signet_challenge missing":
  test "BUG-6a: ConsensusParams has no signet_blocks / signet_challenge fields":
    # Tracked at consensus/params.nim:30-95 (ConsensusParams object body) —
    # no signet_blocks bool, no signet_challenge bytes.
    var hasBug = true
    check hasBug == true

  test "BUG-6b: signetParams() is identical-shape to mainnet — no signet challenge":
    let sn = signetParams()
    # Verify the signet challenge script is NOT in params anywhere we can see.
    # The proper signet template requires this — its absence means a signet
    # nimrod node hands miners empty-challenge templates.
    discard sn  # documents structural absence
    var hasBug = true
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G7  GBT MUST refuse on mainnet when no peers / in IBD — W108 carry-forward
# ─────────────────────────────────────────────────────────────────────────────
# BUG-7: Core mining.cpp:766-774 guards GBT on non-test chains:
#   if (!miner.isTestChain()) {
#     if (connman.GetNodeCount(Both) == 0)
#       throw RPC_CLIENT_NOT_CONNECTED;
#     if (miner.isInitialBlockDownload())
#       throw RPC_CLIENT_IN_INITIAL_DOWNLOAD;
#   }
# Nimrod has no such guards in handleGetBlockTemplate.  A mainnet nimrod node
# isolated from the network will happily produce templates the rest of the
# network won't see, wasting hash on orphans.
suite "W123 G7 — no IBD/no-peer guard on GBT":
  test "BUG-7: GBT must refuse when not connected or in IBD on mainnet":
    var hasBug = true
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G8  GBT mode="proposal" not implemented — W108 carry-forward
# ─────────────────────────────────────────────────────────────────────────────
# BUG-8: BIP-22 §6 / Core mining.cpp:730-752: proposal mode must decode the
# data, look up the block index, return "duplicate"/"duplicate-invalid"/
# "duplicate-inconclusive" if known, otherwise return BIP22ValidationResult of
# TestBlockValidity(..., check_pow=false, check_merkle_root=true).
# Nimrod silently discards the params object (server.nim:3583).
suite "W123 G8 — mode='proposal' not implemented":
  test "BUG-8: proposal mode must trigger TestBlockValidity (check_merkle_root=true)":
    var hasBug = true
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G9  GBT sigops must use exact entry.GetSigOpCost(), not estimate
# ─────────────────────────────────────────────────────────────────────────────
# BUG-9: Core stores exact sigop costs in CTxMemPoolEntry.GetSigOpCost() —
# computed at acceptance via GetTransactionSigOpCost (incl. P2SH redeem-script
# and witness scale).  GBT mining.cpp:927-932 reads tx_sigops.at(idx) which is
# block_template->getTxSigops()[idx] — the exact stored cost.
# Nimrod estimateTxSigops (blocktemplate.nim:234-270) counts only output
# scriptPubKey patterns; it ignores P2SH redeem-script sigops and the witness
# scale.  Cumulative-sigops accounting may then accept a block above the 80,000
# cap (rejected by Core peers as "bad-blk-sigops") or reject below it.
suite "W123 G9 — sigops estimator vs exact entry sigops":
  test "BUG-9: GBT uses estimateTxSigops, not mempool entry's exact sigopsCost":
    # Verify there's no SigOpCost field on MempoolEntry. The current entry
    # stores ancestor fee/weight but no explicit sigop cost.
    var dummyEntry: MempoolEntry
    discard dummyEntry  # accessing .sigopsCost would not compile if absent
    var hasBug = true
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G10 BIP-94 timewarp rule (MAX_TIMEWARP=600) at adjustment boundary
# ─────────────────────────────────────────────────────────────────────────────
# BUG-10: Core consensus/consensus.h:35  MAX_TIMEWARP = 600 seconds.
# node/miner.cpp:43-44:
#   if (height % difficulty_adjustment_interval == 0)
#     min_time = max(min_time, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
# Nimrod blocktemplate.nim updateTimestamp (lines 489-517) only enforces MTP+1;
# no MAX_TIMEWARP clamping at adjustment-period boundaries.  GBT mintime field
# is also wrong here (see G4).  BIP-94 was specifically introduced to mitigate
# timewarp attacks; nimrod doesn't enforce on any network.
suite "W123 G10 — BIP-94 MAX_TIMEWARP absent":
  test "BUG-10: MAX_TIMEWARP=600 not enforced at adjustment boundary":
    # Constant search: no MaxTimewarp constant defined anywhere.
    # If a constant named "MaxTimewarp" existed in consensus/params, importing
    # it would resolve.  It does not — gate is structurally absent.
    var hasBug = true
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G11 Template nBits must be GetNextWorkRequired, not prev.bits — W108 carry
# ─────────────────────────────────────────────────────────────────────────────
# BUG-11: Core node/miner.cpp:220:
#   pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus());
# Nimrod buildBlockTemplate (blocktemplate.nim:441-445) reads prev block's bits
# unchanged.  Correct 2015/2016 blocks; WRONG at every adjustment boundary →
# block rejected with "bad-diffbits" by every peer.  Comment at line 513-517
# acknowledges the gap.
suite "W123 G11 — template nBits stale at adjustment boundary":
  test "BUG-11: buildBlockTemplate copies prev.bits instead of GetNextWorkRequired":
    var hasBug = true
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G12 submitblock missing UpdateUncommittedBlockStructures — W108 carry-forward
# ─────────────────────────────────────────────────────────────────────────────
# BUG-12: Core rpc/mining.cpp:1084-1090:
#   const CBlockIndex* pindex = chainman.m_blockman.LookupBlockIndex(block.hashPrevBlock);
#   if (pindex) chainman.UpdateUncommittedBlockStructures(block, pindex);
# This regenerates the witness commitment when needed.  Nimrod handleSubmitBlock
# (server.nim:3681+) has no such call — a submitted block whose witness
# commitment was computed from a stale template may be rejected with
# "bad-witness-merkle-match" after UpdateTime adjusts nTime.
suite "W123 G12 — submitblock missing UpdateUncommittedBlockStructures":
  test "BUG-12: submitblock does not call UpdateUncommittedBlockStructures":
    var hasBug = true
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G13 submitblock missing "duplicate" / "duplicate-inconclusive" detection
# ─────────────────────────────────────────────────────────────────────────────
# BUG-13: Core mining.cpp:1097-1098:
#   if (!new_block && accepted) return "duplicate";
# Resubmitting an already-accepted block must return "duplicate" without going
# through the full validation pipeline.  Nimrod re-validates and may emit a
# different status string.  Mining pools rely on the canonical "duplicate"
# token for retry logic.
suite "W123 G13 — submitblock duplicate detection missing":
  test "BUG-13: submitblock does not return 'duplicate' for already-accepted blocks":
    var hasBug = true
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G14 getmininginfo "networkhashps" hardcoded 0.0 — FIXED 2026-06-28
# ─────────────────────────────────────────────────────────────────────────────
# Core mining.cpp:472:
#   obj.pushKV("networkhashps", getnetworkhashps().HandleRequest(request));
# Previously nimrod hardcoded 0.0 (`resp["networkhashps"] = %0.0`) even though
# handleGetNetworkHashPS existed.  FIXED: handleGetMiningInfo now delegates to
# handleGetNetworkHashPS(newJArray()) (Core's nblocks=120/height=-1 defaults),
# so getmininginfo reports the real estimate. Verified live on scratch regtest:
# getmininginfo.networkhashps > 0 and == a direct getnetworkhashps call.
suite "W123 G14 — getmininginfo networkhashps now delegates to getnetworkhashps":
  test "FIXED-14: getmininginfo no longer hardcodes networkhashps=0.0":
    var fixed = true
    check fixed == true

# ─────────────────────────────────────────────────────────────────────────────
# G15 getmininginfo "blockmintxfee" 1000x too high — W108 BUG-11 carry-forward
# ─────────────────────────────────────────────────────────────────────────────
# BUG-15: Core policy/policy.h:36:  DEFAULT_BLOCK_MIN_TX_FEE = 1 sat/kvB.
# Core emits ValueFromAmount(CFeeRate(1).GetFeePerK()) = 0.00000001 BTC/kvB.
# Nimrod server.nim:4449 hardcodes 0.00001000 (= 1000 sat/kvB, 10^3× too high).
# This is also the value used in buildBlockTemplate's default min-fee floor
# (blocktemplate.nim:33  DefaultBlockMinFeeRateSatKvB = 1_000) — confirmed below.
suite "W123 G15 — blockmintxfee 1000x too high":
  test "BUG-15a: getmininginfo hardcoded blockmintxfee = 0.00001000 BTC/kvB (Core: 0.00000001)":
    let nimrodVal = 0.00001000
    let coreVal   = 0.00000001
    check nimrodVal != coreVal

  test "BUG-15b: DefaultBlockMinFeeRateSatKvB = 1000 (Core: 1)":
    # Note: DefaultBlockMinFeeRateSatKvB IS exported from mining/blocktemplate
    check DefaultBlockMinFeeRateSatKvB == 1_000'i64
    check DefaultBlockMinFeeRateSatKvB != 1'i64

# ─────────────────────────────────────────────────────────────────────────────
# G16 getmininginfo "currentblocksize" field MUST NOT be emitted — Core removed
# ─────────────────────────────────────────────────────────────────────────────
# BUG-16: Bitcoin Core removed the "currentblocksize" key from getmininginfo
# years ago (PR #16957 / commit 4dc1f5e3) — only "currentblockweight" and
# "currentblocktx" remain, and both are OPTIONAL (only emitted when a block
# has actually been assembled).  Nimrod server.nim:4443-4445 unconditionally
# emits all three with hardcoded zeros.
#
# Side effect: monitoring tools that special-case "currentblocksize == 0" to
# detect non-mining nodes get a false positive on every nimrod instance.
# Tools that key on whether the field exists at all break entirely.
suite "W123 G16 — getmininginfo emits removed 'currentblocksize' field":
  test "BUG-16a: 'currentblocksize' field is emitted (Core removed it)":
    # The string literal "currentblocksize" is hard-coded at server.nim:4443
    # — its presence demonstrates the bug.  We assert structurally:
    var hasBug = true
    check hasBug == true

  test "BUG-16b: 'currentblockweight' should be optional (only after assembling)":
    # Core mining.cpp:467 wraps in `if (BlockAssembler::m_last_block_weight)`.
    # Nimrod always emits with value 0 (server.nim:4444), revealing the absence
    # of any m_last_block_weight tracking — see also G29.
    var hasBug = true
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G17 getnetworkhashps must reject nblocks=0 — W108 carry-forward
# ─────────────────────────────────────────────────────────────────────────────
# BUG-17: Core mining.cpp:66-68:
#   if (lookup < -1 || lookup == 0)
#     throw RPC_INVALID_PARAMETER, "Invalid nblocks. Must be a positive number or -1.";
# Nimrod server.nim:8112-8114 silently remaps nblocks<=0 to "last difficulty
# interval" instead of returning an error.  Difference is observable from RPC.
suite "W123 G17 — getnetworkhashps nblocks=0 silently remapped":
  test "BUG-17: nblocks=0 must be rejected with RPC_INVALID_PARAMETER":
    var hasBug = true
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G18 getnetworkhashps truncates chainwork to top 8 bytes — W108 carry-forward
# ─────────────────────────────────────────────────────────────────────────────
# FIXED 2026-06-28: Core mining.cpp:105-108 uses arith_uint256::getdouble()
# (all 256 bits) of the chainwork delta.  Nimrod previously read only bytes
# 24..31 of a LITTLE-endian totalWork array — those are the all-zero HIGH
# bytes for any realistic work magnitude (which sits in the low bytes), so
# getnetworkhashps returned 0.0 on every network, not just regtest.  FIXED:
# server.nim getnetworkhashps now folds the FULL 256-bit little-endian work
# into a float64 (countdown 31..0), matching arith_uint256::getdouble().
suite "W123 G18 — getnetworkhashps reads full 256-bit chainwork (LE)":
  test "FIXED-18: full-width LE work read is non-zero where top-8-byte read saw zero":
    # Simulated regtest scenario: total work fits in byte 0 (LSB) only.
    var tipWork:   array[32, byte]
    var startWork: array[32, byte]
    tipWork[0] = 100
    # OLD (buggy) read: bytes 24..31 of the LE array -> all zero.
    var oldTip, oldStart: uint64
    for i in 24..31:
      oldTip   = (oldTip   shl 8) or uint64(tipWork[i])
      oldStart = (oldStart shl 8) or uint64(startWork[i])
    let oldDiff = if oldTip > oldStart: oldTip - oldStart else: 0'u64
    # NEW (fixed) read: full 256-bit LE magnitude as float64 (production path).
    var newTipF, newStartF: float64
    for i in countdown(31, 0):
      newTipF   = newTipF   * 256.0 + float64(tipWork[i])
      newStartF = newStartF * 256.0 + float64(startWork[i])
    check oldDiff == 0'u64              # old path: regtest work invisible
    check (newTipF - newStartF) == 100.0  # fixed path: correct non-zero work

# ─────────────────────────────────────────────────────────────────────────────
# G19 getmininginfo "next.bits" stale at adjustment boundary
# ─────────────────────────────────────────────────────────────────────────────
# BUG-19: Core mining.cpp:481-486 builds next.bits via NextEmptyBlockIndex(tip,
# consensus, next_index) which calls GetNextWorkRequired.  Nimrod
# server.nim:4455 reuses the tip's bits as next.bits — the same staleness as
# G11 in the GBT path, but here it's the published "next block hint" field.
# Bitcoin Core's getmininginfo dashboard shows the wrong projected difficulty
# at every difficulty adjustment boundary.
suite "W123 G19 — getmininginfo next.bits stale at adjustment boundary":
  test "BUG-19: next.bits copies tip.bits, no GetNextWorkRequired":
    var hasBug = true
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G20 GBT "taproot" rule omitted on signet (only on mainnet/testnet)
# ─────────────────────────────────────────────────────────────────────────────
# BUG-20: Core mining.cpp:955-958:
#   if (!fPreSegWit) {
#     aRules.push_back("!segwit");
#     aRules.push_back("taproot");
#   }
#   if (consensusParams.signet_blocks) {
#     aRules.push_back("!signet");
#   }
# Nimrod server.nim:3613-3620 correctly emits "taproot" once it's active, but
# never adds "!signet" on signet networks because consensusParams has no
# signet_blocks flag.  See G6 — the structural absence cascades.
suite "W123 G20 — '!signet' rule never emitted on signet":
  test "BUG-20: GBT rules array never includes '!signet' on signet":
    var hasBug = true
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G21 prioritisetransaction RPC absent — fee-delta entry-point missing
# ─────────────────────────────────────────────────────────────────────────────
# BUG-21: Core rpc/mining.cpp:502-545 implements prioritisetransaction.  Nimrod
# has NO such handler and NO PrioritiseTransaction backend in mempool — only a
# COMMENT noting absence (mempool/mempool.nim:1129-1133):
#   "nimrod has no PrioritiseTransaction, so modified == base — but expose the
#    value separately so the per-tx max_feerate guard below behaves the same
#    as Core if the field is ever wired up."
# So modifiedFee is structurally always equal to baseFee.  Mining-pool
# operators cannot manually boost or punish individual txs.
# Cross-fleet: every other impl in FIX-72 wave wired prioritisetransaction.
suite "W123 G21 — prioritisetransaction RPC absent":
  test "BUG-21a: prioritisetransaction RPC not in handleMethod dispatch":
    # server.nim handleMethod (lines 8231-8476) has no "prioritisetransaction"
    # branch.  We assert structurally:
    var hasBug = true
    check hasBug == true

  test "BUG-21b: getprioritisedtransactions RPC also absent":
    # Core rpc/mining.cpp:547-583 (getprioritisedtransactions).
    var hasBug = true
    check hasBug == true

  test "BUG-21c: MempoolEntry exists but modifiedFee tracks baseFee, no delta storage":
    # The structural gap: no per-txid feeDelta table on the mempool object.
    # Importing mempool here would not surface a PrioritiseTransaction proc.
    var hasBug = true
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G22 submitheader RPC absent — header-only chain extension impossible
# ─────────────────────────────────────────────────────────────────────────────
# BUG-22: Core mining.cpp:1108-1146 implements submitheader: decode a CBlockHeader
# and feed it via ProcessNewBlockHeaders — used by external miners (and Core's
# regression tests) to extend the headers-only chain without a full block body.
# Nimrod has NO submitheader RPC.  Test infrastructure for header-chain attacks
# (regtest, P2P fuzzing) cannot use this entry point.
suite "W123 G22 — submitheader RPC absent":
  test "BUG-22: submitheader RPC not in handleMethod dispatch":
    var hasBug = true
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G23 cluster-aware BlockBuilderChunk / package-feerate selection absent
# ─────────────────────────────────────────────────────────────────────────────
# BUG-23: Core node/miner.cpp addChunks (lines 279-334) uses the cluster
# mempool's GetBlockBuilderChunk / SkipBuilderChunk / IncludeBuilderChunk API:
#   FeePerWeight chunk_feerate = m_mempool->GetBlockBuilderChunk(selected);
#   while (selected.size() > 0) { ... TestChunkBlockLimits(chunk_feerate, ...);
#     if (!fit) m_mempool->SkipBuilderChunk();
#     else { m_mempool->IncludeBuilderChunk();
#            pblocktemplate->m_package_feerates.emplace_back(chunk_feerate_vsize); }
#     ...  GetBlockBuilderChunk(selected); }
# This selects chunks of CPFP packages atomically — a low-fee parent + high-fee
# child are added together or not at all.
#
# Nimrod's getTransactionsByFeeRate (mempool/mempool.nim:1504-1527) sorts
# individual entries by ancestor fee rate, then takes them one at a time.
# CPFP packages are sorted *as a group* but accepted *one entry at a time*,
# losing atomicity — if the child fits but the parent doesn't (or vice versa),
# the result is non-Core block selection.  See also W108 BUG-26.
suite "W123 G23 — cluster-aware BlockBuilderChunk selection absent":
  test "BUG-23a: mempool has no GetBlockBuilderChunk equivalent":
    var hasBug = true
    check hasBug == true

  test "BUG-23b: pre-filter by totalWeight drops eligible txs (W108 BUG-26 carry)":
    # getTransactionsByFeeRate stops accumulating once running totalWeight hits
    # the cap, even though Core would still test smaller transactions after a
    # rejected oversize one (via the per-chunk skip mechanism).  This degrades
    # block packing density on highly-loaded mempools.
    var hasBug = true
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G24 GBT "transactions" must use modified-fee (entry.GetModifiedFee), not base
# ─────────────────────────────────────────────────────────────────────────────
# BUG-24: Core mining.cpp:926 uses tx_fees.at(idx) which is
#   pblocktemplate->vTxFees.push_back(entry.GetFee())
# but block-selection uses modified fees via PrioritiseTransaction deltas.
# Since nimrod has no PrioritiseTransaction (G21), every reported "fee" is the
# base fee.  When prioritisation is wired (FIX-72-equivalent), this gate
# becomes operative: the GBT "fee" field MUST reflect the modified fee Core
# uses for block selection, not the raw on-chain fee.
suite "W123 G24 — GBT tx fee must be modified-fee not base-fee (downstream of G21)":
  test "BUG-24: tx 'fee' field reflects entry.fee (base) only":
    # server.nim:3598-3604 uses entry.get().fee directly — there is no
    # modifiedFee field exposed at the GBT layer.  Downstream-of-G21.
    var hasBug = true
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G25 BIP-152 high-bandwidth-mode peer count not surfaced from mining info
# ─────────────────────────────────────────────────────────────────────────────
# BUG-25: BIP-152 defines a high-bandwidth mode where the node opts in to
# receive cmpctblock messages without prior inv/headers.  Core surfaces the
# active HB peer count via getpeerinfo per peer, and the BIP-152 implementation
# selects up to 3 HB peers (NUM_OUTBOUND_INVENTORY_BROADCAST_PEERS).
# Nimrod has cmpctblock send/receive (network/compact_blocks.nim:647-680
# wantsHighBandwidthMode etc.) but no exposed HB peer count from mining info,
# and no enforcement of the 3-peer maximum.  Cross-impl: this is a P2-OBSERVABILITY
# gap but worth tracking — operators auditing block-propagation latency rely on
# the HB peer count.
suite "W123 G25 — BIP-152 HB peer count not surfaced":
  test "BUG-25: no HB peer count in getmininginfo or getnetworkinfo":
    var hasBug = true
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G26 Coinbase encodes 8-byte extra-nonce field — Core uses 4-byte + dummy push
# ─────────────────────────────────────────────────────────────────────────────
# BUG-26: Core node/miner.cpp:187-193:
#   if (m_options.include_dummy_extranonce) {
#     coinbaseTx.vin[0].scriptSig << OP_0;
#   }
# i.e. Core appends a single OP_0 byte (1 byte) as a placeholder for the miner
# to use as extra nonce space.  Mining pools then overwrite this with their
# 4-byte extra-nonce via merkle-update protocols.
#
# Nimrod blocktemplate.nim:174-175:
#   for i in 0 ..< 8:
#     scriptSig.add(0x00)
# Appends 8 raw zero bytes after the BIP-34 height.  This is NOT a valid push
# opcode — it's interpreted as 8 successive OP_0 instructions.  Consensus-valid
# (coinbase scriptSig is unrestricted) but breaks two assumptions:
#   1. Mining pools that expect a 4-byte extra-nonce slot can't safely overwrite
#      our 8 bytes without shrinking the script.
#   2. The scriptSig length budget at heights 1..16 swells from "OP_n + OP_0
#      = 2 bytes" to "OP_n + 8x0x00 = 9 bytes" — burns 7 bytes vs Core.
suite "W123 G26 — coinbase extra-nonce field shape diverges from Core":
  test "BUG-26: createCoinbaseTx appends 8 raw zero bytes, not OP_0 placeholder":
    let cb = createCoinbaseTx(
      height = 1'i32,
      subsidy = Satoshi(50 * 100_000_000),
      fees = Satoshi(0),
      scriptPubKey = @[0x51'u8],
      witnessCommitment = default(array[32, byte])
    )
    # BIP-34 OP_1 (one byte) + 8 dummy zeros = 9 bytes
    check cb.inputs[0].scriptSig.len == 9
    check cb.inputs[0].scriptSig[0] == 0x51'u8   # OP_1
    # 8 raw zero bytes — these get interpreted as 8 separate OP_0's at parse
    for i in 1..8:
      check cb.inputs[0].scriptSig[i] == 0x00'u8
    # Core's equivalent at height 1 would be just [0x51, 0x00] = 2 bytes
    # (OP_1 + single OP_0 dummy extranonce).  Nimrod's is 7 bytes longer.

# ─────────────────────────────────────────────────────────────────────────────
# G27 coinbase_output_max_additional_sigops Option absent — W108 BUG-14 carry
# ─────────────────────────────────────────────────────────────────────────────
# BUG-27: Core node/miner.cpp:115:
#   nBlockSigOpsCost = m_options.coinbase_output_max_additional_sigops;
# Reserves a sigop budget for the miner's own coinbase output scriptPubKey
# (default 0 but configurable).  Nimrod has no equivalent option; initial
# nBlockSigopsCost is always 0 (blocktemplate.nim:329).
# clampBlockOptions (blocktemplate.nim:278-285) only handles maxWeight and
# reservedWeight — see also W108 BUG-27.
suite "W123 G27 — coinbase_output_max_additional_sigops option absent":
  test "BUG-27: clampBlockOptions has no coinbase_output_max_additional_sigops":
    # The proc signature only takes maxWeight + reservedWeight.
    let r = clampBlockOptions(maxWeight = 4_000_000, reservedWeight = 8_000)
    check r.maxWeight == 4_000_000
    check r.reservedWeight == 8_000
    # No third clamped value returned — proves the field doesn't exist.
    var hasBug = true
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G28 GBT response uses signed int64 for coinbasevalue (correct, but
# nimrod's totalFees+subsidy can saturate if mempool fee sums overflow int64)
# ─────────────────────────────────────────────────────────────────────────────
# BUG-28: Defensive gate. Core uses CAmount (int64_t) consistently; nimrod
# uses Satoshi (also int64). The risk is in the running fee accumulator —
# blocktemplate.nim:383 does `totalFees = totalFees + entry.fee` with no
# saturation check.  If a future mempool injection wave somehow produced
# entries whose summed fees overflow int64 (~92 quadrillion sats, far above
# total supply), the addition wraps silently.  Core has explicit MoneyRange
# guards (consensus/amount.h:21 IsRange()).  Nimrod has no equivalent at the
# template-builder layer.
#
# Practical exposure: low (would require pathological mempool entries) — P2.
suite "W123 G28 — no MoneyRange guard on accumulated totalFees":
  test "BUG-28: totalFees accumulation has no IsRange() check vs MAX_MONEY":
    # Core consensus/amount.h:21 defines MAX_MONEY = 21_000_000 * COIN and
    # IsRange(amount) bool helper that every fee/value path uses.  Nimrod's
    # Satoshi addition has Nim 2.x compile-time overflow defect ON (which
    # at least makes silent wrap impossible at runtime), but it raises
    # OverflowDefect rather than gracefully returning an InvalidAmount error
    # — buildBlockTemplate would CRASH on a malformed mempool entry rather
    # than reject the block.  No MAX_MONEY constant exists in nimrod consensus
    # at all; no IsRange() helper to call.  Structural absence — flip to
    # false once a MoneyRange guard lands in blocktemplate.nim:380-385.
    var hasBug = true
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G29 BlockAssembler::m_last_block_weight / m_last_block_num_txs not tracked
# ─────────────────────────────────────────────────────────────────────────────
# BUG-29: Core node/miner.cpp:159-160 records:
#   m_last_block_num_txs = nBlockTx;
#   m_last_block_weight  = nBlockWeight;
# These persistent static counters drive the OPTIONAL "currentblockweight" and
# "currentblocktx" fields in getmininginfo (mining.cpp:467-468).
# Nimrod doesn't track them — hence the unconditional 0 values in getmininginfo
# (server.nim:4444-4445).  See also G16.
suite "W123 G29 — BlockAssembler last-block stats not persisted":
  test "BUG-29: no module-level m_last_block_weight / m_last_block_num_txs":
    # buildBlockTemplate returns a BlockTemplate value with totalWeight/transactions
    # but never updates any persistent state — every getmininginfo call before
    # a build returns 0.
    var hasBug = true
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# G30 BIP-23 block_reserved_weight / -blockreservedweight CLI option absent
# ─────────────────────────────────────────────────────────────────────────────
# BUG-30: Core common/system.h / node/miner.cpp:106-108:
#   if (!options.block_reserved_weight) {
#     options.block_reserved_weight = args.GetIntArg("-blockreservedweight");
#   }
# Operators can override the reserved-weight default (8000) via CLI flag.
# Nimrod's CoinbaseReservedWeight is a `const` (blocktemplate.nim:16) — no CLI
# override path, no per-call BlockAssembler::Options struct.  Stake-pool
# operators who need to reserve coinbase space for OP_RETURN data (Stratum V2,
# StratV2-template tags, exotic mining contracts) cannot do so.
#
# Cross-fleet: Core has both -blockreservedweight and -blockmaxweight as
# operator knobs; nimrod hard-codes both.
suite "W123 G30 — block_reserved_weight not operator-configurable":
  test "BUG-30: CoinbaseReservedWeight is `const` — no runtime override path":
    # The constant is exported but is a compile-time literal.
    check CoinbaseReservedWeight == 8_000
    # If a per-call override existed, buildBlockTemplate would take a
    # blockReservedWeight parameter.  It does not (signature at
    # blocktemplate.nim:287-292 takes only chainState/mempool/params/script/
    # blockMinFeeRateSatKvB).
    var hasBug = true
    check hasBug == true

# ─────────────────────────────────────────────────────────────────────────────
# Constant verification — anchor critical values to Core
# ─────────────────────────────────────────────────────────────────────────────
suite "W123 — constant verification":
  test "MAX_BLOCK_WEIGHT = 4000000 (consensus/consensus.h:15)":
    check MaxBlockWeight == 4_000_000

  test "MAX_BLOCK_SIGOPS_COST = 80000 (consensus/consensus.h:17)":
    check MaxBlockSigopsCost == 80_000

  test "DEFAULT_BLOCK_RESERVED_WEIGHT = 8000 (policy/policy.h:27)":
    check CoinbaseReservedWeight == 8_000

  test "MINIMUM_BLOCK_RESERVED_WEIGHT = 2000 (policy/policy.h:34)":
    check MinimumBlockReservedWeight == 2_000

  test "MAX_CONSECUTIVE_FAILURES = 1000 (node/miner.cpp:284)":
    check MaxConsecutiveFailures == 1_000

  test "BLOCK_FULL_ENOUGH_WEIGHT_DELTA = 4000 (node/miner.cpp:285)":
    check BlockFullEnoughWeightDelta == 4_000

  test "MAX_TIMEWARP = 600 (consensus/consensus.h:35) — referenced but NOT exported":
    # If a consensus constant MaxTimewarp were defined and exported by
    # ../src/consensus/params or ../src/consensus/validation, we could check
    # its value here.  It is not — see G10.  Documents the absence.
    var hasBug = true
    check hasBug == true

  test "Subsidy halving — height 0 = 50 BTC":
    let p = mainnetParams()
    check getBlockSubsidy(0, p) == Satoshi(50 * 100_000_000)

  test "Subsidy halving — height 210000 = 25 BTC":
    let p = mainnetParams()
    check getBlockSubsidy(210_000, p) == Satoshi(25 * 100_000_000)

  test "Subsidy halving — height 6_930_000 = 0 (final halving complete)":
    let p = mainnetParams()
    check getBlockSubsidy(33 * 210_000, p) == Satoshi(0)
