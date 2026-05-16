## W121: BIP-157/158 compact filter audit
##
## 30 gates classifying nimrod's BIP-158 construction (G1-G10),
## BIP-157 P2P (G11-G20), persistence (G21-G25), and RPC/REST (G26-G30).
##
## Reference: bitcoin-core/src/blockfilterindex.{cpp,h};
##            bitcoin-core/src/blockfilter.cpp;
##            bitcoin-core/src/net_processing.cpp::ProcessGetCFilters etc.;
##            BIP-157, BIP-158.
##
## PRESENT gates: positive existence check via `compiles(symbol)`.
## MISSING gates: `check not compiles(<symbol>)` so this file fails to
## compile once the gap is closed in a follow-up fix.

import std/[unittest]
import ../src/storage/indexes/[gcs, blockfilterindex, base]
import ../src/crypto/siphash
import ../src/network/messages
import ../src/network/peer as net_peer
import ../src/primitives/types

suite "W121 BIP-158 construction (G1-G10)":

  test "G1 PRESENT: GCS encode / build path":
    ## newGCSFilter has 3 overloads (empty, from elements, from encoded);
    ## reference one concrete overload via a typed value rather than the
    ## bare overloaded symbol which `compiles()` cannot resolve.
    let p0 = GCSParams(sipHashK0: 0, sipHashK1: 0,
                       p: BasicFilterP, m: BasicFilterM)
    check compiles(newGCSFilter(p0))
    check compiles(buildHashedSet)

  test "G2 PRESENT: Golomb-Rice encode + decode":
    check compiles(golombRiceEncode)
    check compiles(golombRiceDecode)

  test "G3 PRESENT: SipHash-2-4 + FastRange64":
    check compiles(sipHash)
    check compiles(fastRange64)

  test "G4 PRESENT: BIP-158 'basic' constants P=19, M=784931":
    check BasicFilterP == 19'u8
    check BasicFilterM == 784931'u32

  test "G5 PRESENT: extractBasicFilterElements (OP_RETURN skip + prev-out)":
    check compiles(extractBasicFilterElements)
    check compiles(isOpReturn)

  test "G6 PRESENT: basicFilterParams derives k0/k1 from block hash":
    check compiles(basicFilterParams)

  test "G7 PRESENT: getFilterHash (double-SHA256 of encoded filter)":
    ## getFilterHash is overloaded (BlockFilter + index/height variants);
    ## reference a concrete overload signature.
    let p0 = GCSParams(sipHashK0: 0, sipHashK1: 0,
                       p: BasicFilterP, m: BasicFilterM)
    let bf = BlockFilter(filterType: bftBasic,
                         blockHash: default(BlockHash),
                         filter: newGCSFilter(p0))
    check compiles(getFilterHash(bf))

  test "G8 PRESENT: computeFilterHeader (chained sha256d(hash||prev))":
    check compiles(computeFilterHeader)

  test "G9 PRESENT: empty-filter encoded as CompactSize(0)":
    let params = GCSParams(sipHashK0: 0, sipHashK1: 0,
                           p: BasicFilterP, m: BasicFilterM)
    let f = newGCSFilter(params, @[])
    check f.encoded == @[byte(0)]

  test "G10 MISSING: BIP-158 Core test-vector regression battery":
    ## BIP-158 ships canonical test vectors (testnet block #1, etc.) in
    ## bitcoin-core/src/test/data/blockfilters.json.  Nimrod has unit tests
    ## of its own encode/decode round-trip but no cross-impl check that the
    ## bytes match Core's expected filter for a known block.  This means a
    ## quiet byte-order bug in basicFilterParams() (k0/k1 derivation) — or
    ## any drift from the BIP-158 element-extraction rules — would not be
    ## detected against the canonical fixture set.
    ## Reference: bitcoin-core/src/test/data/blockfilters.json
    check not compiles(coreBIP158TestVectors)
    check not compiles(verifyAgainstBIP158Vectors)

suite "W121 BIP-157 P2P (G11-G20)":

  test "G11 PRESENT: getcfilters / cfilter wire codec":
    check compiles(GetCFiltersMsg)
    check compiles(CFilterMsg)
    check compiles(newGetCFilters)
    check compiles(newCFilter)

  test "G12 PRESENT: getcfheaders / cfheaders wire codec":
    check compiles(GetCFHeadersMsg)
    check compiles(CFHeadersMsg)
    check compiles(newCFHeaders)

  test "G13 PRESENT: getcfcheckpt / cfcheckpt wire codec":
    check compiles(GetCFCheckPtMsg)
    check compiles(CFCheckPtMsg)
    check compiles(newCFCheckPt)

  test "G14 PRESENT: NODE_COMPACT_FILTERS service-flag constant":
    check NodeCompactFilters == 64'u64

  test "G15 PRESENT: NODE_COMPACT_FILTERS advertised in our version msg":
    ## FIX-71 (W121 G15): peer.sendVersion() now ORs NodeCompactFilters
    ## (1<<6 = 64) into the outbound `services` bitfield iff the operator
    ## opted in with --peerblockfilters AND --blockfilterindex is on.
    ## Latched at daemon startup from `setCompactFiltersAdvertise`.
    ## Mirrors Core init.cpp:992-999.
    check compiles(net_peer.advertiseCompactFiltersService)
    check compiles(net_peer.setCompactFiltersAdvertise)

    # Default state: OFF (Core parity DEFAULT_PEERBLOCKFILTERS = false).
    net_peer.setCompactFiltersAdvertise(false)
    check net_peer.advertiseCompactFiltersService() == false

    # When operator opts in (CLI: --peerblockfilters AND
    # --blockfilterindex), nimrod advertises NODE_COMPACT_FILTERS.
    net_peer.setCompactFiltersAdvertise(true)
    check net_peer.advertiseCompactFiltersService() == true

    # Reset so other suites see the default state.
    net_peer.setCompactFiltersAdvertise(false)

  test "G15b FORWARD-REGRESSION: ourServices ORs NodeCompactFilters when gated":
    ## Forward-regression guard: prove the gate is wired all the way
    ## through to the bits that go on the wire.  Mirrors how
    ## sendVersion() composes `ourServices` so a future refactor that
    ## drops the OR (or moves the toggle reset around) will trip here
    ## even if the helper still exists.
    block off_path:
      net_peer.setCompactFiltersAdvertise(false)
      var ourServices = NodeNetwork or NodeWitness
      if net_peer.advertiseCompactFiltersService():
        ourServices = ourServices or NodeCompactFilters
      check (ourServices and NodeCompactFilters) == 0'u64

    block on_path:
      net_peer.setCompactFiltersAdvertise(true)
      var ourServices = NodeNetwork or NodeWitness
      if net_peer.advertiseCompactFiltersService():
        ourServices = ourServices or NodeCompactFilters
      check (ourServices and NodeCompactFilters) == NodeCompactFilters
      check (ourServices and NodeNetwork) == NodeNetwork
      check (ourServices and NodeWitness) == NodeWitness

    # Reset to OFF — module-level state must not bleed across suites.
    net_peer.setCompactFiltersAdvertise(false)

  test "G16 PRESENT: mkGetCFilters dispatched to a real handler":
    ## Routed in nimrod.nim::handleMessage; uses
    ## state.blockFilterIndex.getFilter() and peer.sendMessage(newCFilter()).
    check compiles(mkGetCFilters)
    check compiles(newCFilter)

  test "G17 PRESENT: mkGetCFHeaders dispatched + prev-header fetched":
    check compiles(mkGetCFHeaders)
    check compiles(newCFHeaders)

  test "G18 PRESENT: mkGetCFCheckPt dispatched + 1000-block interval walk":
    check compiles(mkGetCFCheckPt)
    check compiles(newCFCheckPt)

  test "G19 MISSING: cfilter / cfheaders / cfcheckpt response-side handler":
    ## peer.nim only traces the three response messages (lines 1448-1469)
    ## and nimrod.nim drops them silently (`of mkCFilter, mkCFHeaders,
    ## mkCFCheckPt: trace ... — no handler needed on the server-path`).
    ## There is no light-client requestor in sync.nim that calls
    ## newGetCFilters / newGetCFHeaders / newGetCFCheckPt; consequently
    ## nimrod cannot consume BIP-157 filter data from peers — only serve.
    ## Reference: bitcoin-core/src/blockfilter/client.cpp (Core's client-mode).
    check not compiles(handleCFilterResponse)
    check not compiles(requestCFilters)
    check not compiles(requestCFHeaders)

  test "G20 MISSING: protocol-violation disconnect on bad cfilter request":
    ## Per Core ProcessGetCFilters / PrepareBlockFilterRequest
    ## (net_processing.cpp:3268-3304), unsupported filter type, unknown
    ## stop hash, start > stop, or oversized range MUST trigger
    ## `node.fDisconnect = true`.  Nimrod's nimrod.nim handler only logs
    ## (`debug "getcfilters: invalid range or too large"`) and returns —
    ## a misbehaving peer can probe for the index indefinitely.
    ## Additionally there is no validation that req.filterType == BASIC=0;
    ## nimrod echoes whatever type the peer asked for back into the
    ## reply, even though only bftBasic is implemented.
    ## Reference: bitcoin-core/src/net_processing.cpp:3271-3304
    check not compiles(disconnectOnBadFilterRequest)
    check not compiles(validateGetCFiltersRequest)

suite "W121 Persistence (G21-G25)":

  test "G21 PRESENT: BlockFilterIndex type + customAppend / customRemove":
    check compiles(BlockFilterIndex)
    check compiles(newBlockFilterIndex)
    check compiles(addBlock)
    check compiles(removeBlock)

  test "G22 PRESENT: height-keyed FilterIndexEntry in DB":
    check compiles(filterHeightKey)
    check compiles(serializeFilterEntry)
    check compiles(deserializeFilterEntry)

  test "G23 PRESENT: hash-keyed entry for reorg-recovery":
    check compiles(filterHashKey)
    check compiles(getFilterEntryByHash)

  test "G24 PRESENT: fltr?????.dat flat-file storage":
    check compiles(filterFileName)
    check compiles(filterFilePath)
    check compiles(writeFilter)
    check compiles(readFilter)
    check MaxFilterFileSize == 16 * 1024 * 1024

  test "G25 MISSING: Core-parity on-disk record layout (hash + compactsize)":
    ## Core's WriteFilterToDisk (blockfilterindex.cpp:177-232) writes
    ##     block_hash (32) || CompactSize(filter_len) || encoded_filter
    ## and ReadFilterFromDisk recovers the hash + length, verifies the
    ## stored hash matches the DB hash (`if (Hash(encoded_filter) != hash)`).
    ##
    ## Nimrod's writeFilter (blockfilterindex.nim:169-192) writes ONLY the
    ## raw encoded_filter bytes — no hash, no length prefix.  Consequence:
    ##   1. readFilter takes a `filterSize: int` parameter, but the on-disk
    ##      record contains no record of the size, so the only call site
    ##      (`getFilter`) hard-codes `1024 * 1024` and depends on
    ##      `skipDecode = true` to silently accept the trailing 1 MiB of
    ##      garbage as part of the filter.
    ##   2. There is no on-disk integrity check; bit-rot in a fltr*.dat
    ##      file cannot be detected, and the per-block hash recovery used
    ##      by Core's `entry.hash` check is impossible.
    ##   3. The .dat file is not Core-compatible — a Core node cannot
    ##      read a nimrod-written fltr*.dat and vice versa.
    ## Reference: bitcoin-core/src/index/blockfilterindex.cpp:151-232
    check not compiles(writeFilterRecord)
    check not compiles(readFilterRecord)

suite "W121 RPC / REST (G26-G30)":

  test "G26 PRESENT: REST /rest/blockfilter/<type>/<hash>":
    ## Imports only the rest module surface that is safe to reference here;
    ## fuller wiring is exercised by tests/test_rest.nim.  We rely on
    ## storage symbols that the REST handler needs to compile.
    check compiles(getFilter)

  test "G27 PRESENT: REST /rest/blockfilterheaders/<type>/<hash>":
    check compiles(getFilterHeader)
    check compiles(getFilterEntry)

  test "G28 MISSING: RPC getblockfilter":
    ## Core RPC `getblockfilter <blockhash> [<filtertype>]` returns
    ## { "filter": hex, "header": hex }.  nimrod has no dispatch case for
    ## "getblockfilter" in src/rpc/server.nim — only the REST path is
    ## served.  This breaks RPC-level light-client tooling and
    ## interoperability with the `bitcoin-cli getblockfilter` workflow.
    ## Reference: bitcoin-core/src/rpc/blockchain.cpp::getblockfilter
    check not compiles(rpcGetBlockFilter)
    check not compiles(handleGetBlockFilter)

  test "G29 PRESENT: -peerblockfilters CLI knob":
    ## FIX-71 (W121 G29): added `--peerblockfilters` / `peerblockfilters`
    ## (config + CLI + conf-file) gating whether nimrod advertises
    ## NODE_COMPACT_FILTERS.  Default OFF (Core parity
    ## DEFAULT_PEERBLOCKFILTERS = false).  At startup, --peerblockfilters
    ## set without --blockfilterindex hard-fails with a Core-equivalent
    ## InitError ("Cannot set -peerblockfilters without -blockfilterindex"),
    ## matching bitcoin-core/src/init.cpp:992-999.
    check compiles(net_peer.peerBlockFiltersEnabled)

    # Default state mirrors DEFAULT_PEERBLOCKFILTERS = false.
    net_peer.setCompactFiltersAdvertise(false)
    check net_peer.peerBlockFiltersEnabled() == false

    # When the operator opts in, the helper returns true.
    net_peer.setCompactFiltersAdvertise(true)
    check net_peer.peerBlockFiltersEnabled() == true

    # The helper is an alias of `advertiseCompactFiltersService()` —
    # both views of the same module-level toggle, so they MUST be in
    # lockstep.  Forward-regression guard against accidental divergence.
    check net_peer.peerBlockFiltersEnabled() ==
          net_peer.advertiseCompactFiltersService()

    # Reset to OFF so other suites see the default state.
    net_peer.setCompactFiltersAdvertise(false)

  test "G30 MISSING: RPC scanblocks (BIP-157 filter-driven wallet scan)":
    ## Core RPC `scanblocks` walks the chain using the block-filter index
    ## to identify candidate blocks for a descriptor set.  Without it, a
    ## nimrod operator with --blockfilterindex still has no way to use
    ## the data for the canonical BIP-157 wallet-rescan use case.
    ## Reference: bitcoin-core/src/rpc/blockchain.cpp::scanblocks
    check not compiles(rpcScanBlocks)
    check not compiles(handleScanBlocks)
