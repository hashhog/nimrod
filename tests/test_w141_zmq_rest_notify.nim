## W141 — ZMQ + REST + Notification scripts audit (30 gates, xfail
## regression guards).
##
## Audit type: discovery (NO production code change in W141).
##
## W141 catalogues the gap between Bitcoin Core's transport + notify
## surface and nimrod's parallel pipeline:
##   - bitcoin-core/src/zmq/zmqnotificationinterface.cpp
##     (Create / Initialize / Shutdown / UpdatedBlockTip /
##      BlockConnected / BlockDisconnected / TransactionAddedToMempool /
##      TransactionRemovedFromMempool / GetActiveNotifiers /
##      TryForEachAndRemoveFailed)
##   - bitcoin-core/src/zmq/zmqpublishnotifier.cpp
##     (Initialize / Shutdown / SendZmqMessage 3-part wire /
##      IsZMQAddressIPV6 / ZMQ_IPV6 socket option / SendSequenceMsg)
##   - bitcoin-core/src/rest.cpp
##     (rest_chaininfo / rest_deploymentinfo / rest_block_part /
##      rest_spent_txouts / rest_getutxos binary format / rest_headers
##      new-form query param / rest_mempool / ParseDataFormat /
##      CheckWarmup / uri_prefixes[] table)
##   - bitcoin-core/src/init.cpp:2009 (-blocknotify)
##   - bitcoin-core/src/wallet/wallet.cpp:1162 (-walletnotify)
##   - bitcoin-core/src/node/kernel_notifications.cpp:30 (-alertnotify)
##   - bitcoin-core/src/common/system.cpp (runCommand + ShellEscape)
##
## ...and nimrod's parallel pipeline:
##   - src/rpc/zmq.nim                (full ZMQ publisher; ORPHANED)
##   - src/rpc/rest.nim               (REST HTTPS listener + handlers)
##   - src/nimrod.nim                 (CLI flags; no -*notify, no -zmq*)
##   - src/rpc/server.nim             (RPC; no getzmqnotifications)
##
## Method: each test asserts the CURRENT (buggy / absent) behaviour
## with a `check` that pins the gap. When a future FIX wave closes
## the gap, the test will fail loudly and the developer must flip
## the assertion (per W120 / W122 / W123 / W124 / W125 / W128 / W131 /
## W132 / W133 / W134 / W135 / W136 / W137 / W138 methodology).

import unittest2
import std/[options, strutils, tables, sets, sequtils]
import ../src/rpc/zmq
import ../src/rpc/rest
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc makeBlockHash(v: byte): BlockHash =
  var h: array[32, byte]
  h[0] = v
  BlockHash(h)

proc makeTxId(v: byte): TxId =
  var h: array[32, byte]
  h[0] = v
  TxId(h)

# Read production source files once for source-level pinning.
let
  zmqSrc:     string = readFile("src/rpc/zmq.nim")
  restSrc:    string = readFile("src/rpc/rest.nim")
  nimrodSrc:  string = readFile("src/nimrod.nim")
  serverSrc:  string = readFile("src/rpc/server.nim")

# ---------------------------------------------------------------------------
# G1 — ZMQ_IPV6 socket option set based on IPv6 address (BUG-1, P0-WIRE)
# ---------------------------------------------------------------------------
suite "W141 G1 — ZMQ_IPV6 socket option (BUG-1)":

  test "G1 BUG-1: ZMQ_IPV6 constant declared but never zmq_setsockopt'd":
    ## Core zmqpublishnotifier.cpp:82-93 inspects address, then
    ## :130-136 calls zmq_setsockopt(ZMQ_IPV6, ...) BEFORE zmq_bind.
    ## Nimrod's initialize() only sets ZMQ_SNDHWM + ZMQ_TCP_KEEPALIVE.
    check "ZMQ_IPV6" in zmqSrc                   # constant declared
    let initBlock =
      zmqSrc[zmqSrc.find("proc initialize*(notifier: var ZmqNotifier") ..
             zmqSrc.find("addressToSocket[notifier.address]")]
    # No setsockopt call mentions ZMQ_IPV6 inside initialize:
    check "ZMQ_IPV6" notin initBlock
    # And no helper detecting whether the address is IPv6:
    check "isZmqAddressIpv6" notin zmqSrc
    check "IsZMQAddressIPV6" notin zmqSrc

# ---------------------------------------------------------------------------
# G2 — Multipart wire format (PRESENT)
# ---------------------------------------------------------------------------
suite "W141 G2 — 3-part multipart wire [topic][body][LE32 seq]":

  test "G2 PRESENT: writeLE32 used for sequence byte":
    var data: array[4, byte]
    writeLE32(data, 0, 0x12345678'u32)
    # LE byte order: low byte first
    check data == [byte(0x78), 0x56, 0x34, 0x12]

  test "G2 PRESENT: ZMQ_SNDMORE flag wires 3-part chain":
    check ZMQ_SNDMORE == 2          # libzmq ZMQ_SNDMORE = 2

# ---------------------------------------------------------------------------
# G3 — Per-notifier sequence increments on success (PRESENT)
# ---------------------------------------------------------------------------
suite "W141 G3 — per-notifier sequence":

  test "G3 PRESENT: ZmqNotifier has `sequence: uint32` field":
    check "sequence*: uint32" in zmqSrc or "sequence: uint32" in zmqSrc

  test "G3 PRESENT: sendZmqMessage increments sequence on success only":
    let sendBlock =
      zmqSrc[zmqSrc.find("proc sendZmqMessage*(notifier") ..
             zmqSrc.find("proc initialize*(notifier: var ZmqNotifier")]
    check "inc notifier.sequence" in sendBlock
    check "if result:" in sendBlock

# ---------------------------------------------------------------------------
# G4 — Socket reuse across notifiers sharing an address (PRESENT)
# ---------------------------------------------------------------------------
suite "W141 G4 — socket reuse":

  test "G4 PRESENT: addressToSocket table reused across notifiers":
    var config = newZmqConfig()
    config.hashBlockAddresses.add("tcp://127.0.0.1:28332")
    config.hashTxAddresses.add("tcp://127.0.0.1:28332")
    let zmq = newZmqNotificationInterface(config, nil)
    let active = zmq.getActiveNotifiers()
    # 2 notifiers, same address — should share socket once both initialized
    check active.len == 2
    check active[0].address == active[1].address

# ---------------------------------------------------------------------------
# G5 — DEFAULT_ZMQ_SNDHWM = 1000 (PRESENT)
# ---------------------------------------------------------------------------
suite "W141 G5 — default high water mark":

  test "G5 PRESENT: DEFAULT_ZMQ_SNDHWM == 1000 (Core abstractnotifier.cpp:9)":
    check DEFAULT_ZMQ_SNDHWM == 1000

  test "G5 PRESENT: ZMQ_SNDHWM == 23 (libzmq constant)":
    check ZMQ_SNDHWM == 23

# ---------------------------------------------------------------------------
# G6 — ZMQ_TCP_KEEPALIVE = 1 (PRESENT)
# ---------------------------------------------------------------------------
suite "W141 G6 — TCP keepalive":

  test "G6 PRESENT: ZMQ_TCP_KEEPALIVE == 34 (libzmq constant)":
    check ZMQ_TCP_KEEPALIVE == 34

  test "G6 PRESENT: keepalive=1 set during initialize":
    check "ZMQ_TCP_KEEPALIVE" in zmqSrc

# ---------------------------------------------------------------------------
# G7 — ZMQ_LINGER = 0 on shutdown (PRESENT)
# ---------------------------------------------------------------------------
suite "W141 G7 — LINGER=0 on shutdown":

  test "G7 PRESENT: ZMQ_LINGER == 17 (libzmq constant)":
    check ZMQ_LINGER == 17

  test "G7 PRESENT: shutdown sets linger=0 before zmq_close":
    let shutdownBlock =
      zmqSrc[zmqSrc.find("proc shutdown*(notifier: var ZmqNotifier") ..
             zmqSrc.find("proc newZmqConfig")]
    check "linger" in shutdownBlock or "ZMQ_LINGER" in shutdownBlock
    check "linger: cint = 0" in shutdownBlock

# ---------------------------------------------------------------------------
# G8 — Hash byte-order reversed for wire (PRESENT)
# ---------------------------------------------------------------------------
suite "W141 G8 — hash byte order on wire":

  test "G8 PRESENT: reverseBytes reverses 32-byte array":
    var input: array[32, byte]
    for i in 0 ..< 32: input[i] = byte(i)
    let rev = reverseBytes(input)
    check rev[0] == byte(31)
    check rev[31] == byte(0)

  test "G8 PRESENT: notifyBlock reverses the BlockHash":
    check "reverseBytes(array[32, byte](blockHash))" in zmqSrc

# ---------------------------------------------------------------------------
# G9 — Sequence body shape (PRESENT)
# ---------------------------------------------------------------------------
suite "W141 G9 — sequence body shape":

  test "G9 PRESENT: block-connect/disconnect = 33 bytes (32 hash + 1 label)":
    var data: array[33, byte]
    let hashBytes = reverseBytes(array[32, byte](makeBlockHash(0xab)))
    copyMem(addr data[0], unsafeAddr hashBytes[0], 32)
    data[32] = byte(SEQ_CONNECTED)
    check data.len == 33
    check data[32] == byte('C')

  test "G9 PRESENT: mempool-add/remove = 41 bytes (32+1+8 LE seq)":
    var data: array[41, byte]
    data[32] = byte(SEQ_ADDED)
    writeLE64(data, 33, 12345'u64)
    check data.len == 41
    check data[32] == byte('A')
    check data[33] == byte(12345 and 0xff)

  test "G9 PRESENT: SEQ labels match Core (A/R/C/D)":
    check byte(SEQ_ADDED)        == byte('A')
    check byte(SEQ_REMOVED)      == byte('R')
    check byte(SEQ_CONNECTED)    == byte('C')
    check byte(SEQ_DISCONNECTED) == byte('D')

# ---------------------------------------------------------------------------
# G10 — unix:// → ipc:// prefix rewrite (BUG-2, P3)
# ---------------------------------------------------------------------------
suite "W141 G10 — unix://-prefix rewrite (BUG-2)":

  test "G10 BUG-2: no unix:// → ipc:// rewrite anywhere in source":
    ## Core zmqnotificationinterface.cpp:62-64 rewrites the prefix
    ## (ADDR_PREFIX_UNIX → ADDR_PREFIX_IPC) before zmq_bind. Nimrod
    ## passes the operator's literal address straight through.
    check "unix://" notin zmqSrc
    check "ADDR_PREFIX_UNIX" notin zmqSrc
    check "ADDR_PREFIX_IPC"  notin zmqSrc

  test "G10 BUG-2: literal unix:///path/sock would be passed to zmq_bind unchanged":
    var config = newZmqConfig()
    config.hashBlockAddresses.add("unix:///tmp/nimrod-zmq.sock")
    let zmq = newZmqNotificationInterface(config, nil)
    let active = zmq.getActiveNotifiers()
    # Address retained verbatim — no auto-rewrite.
    check active[0].address == "unix:///tmp/nimrod-zmq.sock"

# ---------------------------------------------------------------------------
# G11 — TryForEachAndRemoveFailed semantic (BUG-3, P3)
# ---------------------------------------------------------------------------
suite "W141 G11 — drop-on-failure semantic (BUG-3)":

  test "G11 BUG-3: no removeFailed / TryForEach helper in zmq.nim":
    ## Core zmqnotificationinterface.cpp:133-149 erases the failed
    ## notifier from the live list. Nimrod just `warn`s and retries
    ## on every subsequent block/tx.
    ## (Note: `addressToSocket.del(...)` exists in shutdown — that's a
    ## table-key delete for socket dedup, not the failure-drop semantic.)
    check "removeFailed"              notin zmqSrc
    check "TryForEach"                notin zmqSrc
    check "tryForEachAndRemoveFailed" notin zmqSrc
    # No `notifiers.del(...)` / `notifiers.delete(...)` / `notifiers.erase(...)`:
    check "notifiers.del("    notin zmqSrc
    check "notifiers.delete(" notin zmqSrc
    check "notifiers.erase("  notin zmqSrc

  test "G11 BUG-3: notifyBlock loop only warns on send failure":
    let notifyBlock =
      zmqSrc[zmqSrc.find("proc notifyBlock*(zmq: var ZmqNotificationInterface") ..
             zmqSrc.find("proc notifyRawBlock")]
    check "warn " in notifyBlock
    # No erase / remove call in the failure path:
    check ".delete(" notin notifyBlock
    check "notifiers.del" notin notifyBlock

# ---------------------------------------------------------------------------
# G12 — /rest/chaininfo endpoint (BUG-4, P2)
# ---------------------------------------------------------------------------
suite "W141 G12 — /rest/chaininfo endpoint (BUG-4)":

  test "G12 BUG-4: no chaininfo handler in rest.nim":
    check "handleRestChainInfo" notin restSrc
    check "chaininfo"           notin restSrc

  test "G12 BUG-4: chaininfo route absent from handleRestRequest":
    let routeBlock =
      restSrc[restSrc.find("proc handleRestRequest") ..
              restSrc.find("# ============================================================================\n# HTTP Server")]
    check "chaininfo" notin routeBlock

# ---------------------------------------------------------------------------
# G13 — /rest/deploymentinfo endpoint (BUG-5, P2)
# ---------------------------------------------------------------------------
suite "W141 G13 — /rest/deploymentinfo endpoint (BUG-5)":

  test "G13 BUG-5: no deploymentinfo handler in rest.nim":
    check "handleRestDeploymentInfo" notin restSrc
    check "deploymentinfo"           notin restSrc

  test "G13 BUG-5: deploymentinfo route absent from handleRestRequest":
    let routeBlock =
      restSrc[restSrc.find("proc handleRestRequest") ..
              restSrc.find("# ============================================================================\n# HTTP Server")]
    check "deploymentinfo" notin routeBlock

# ---------------------------------------------------------------------------
# G14 — /rest/blockpart endpoint (BUG-6, P2)
# ---------------------------------------------------------------------------
suite "W141 G14 — /rest/blockpart endpoint (BUG-6)":

  test "G14 BUG-6: no blockpart handler in rest.nim":
    check "handleRestBlockPart" notin restSrc
    check "blockpart"           notin restSrc

# ---------------------------------------------------------------------------
# G15 — /rest/getutxos binary format CompactSize prefixes (BUG-7, P0-WIRE)
# ---------------------------------------------------------------------------
suite "W141 G15 — getutxos binary wire format (BUG-7)":

  test "G15 BUG-7: bitmap emitted with NO CompactSize prefix":
    ## Core rest.cpp:1039-1042:
    ##   ssGetUTXOResponse << active_height << active_hash << bitmap << outs;
    ## where `bitmap` is `std::vector<unsigned char>` — serialized as
    ## `CompactSize(len) || bytes`. Nimrod emits raw bitmap bytes
    ## (rest.nim:700, 730).
    let bin =
      restSrc[restSrc.find("of rfBinary:", restSrc.find("handleRestGetUtxos")) ..
              restSrc.find("of rfHex:", restSrc.find("handleRestGetUtxos"))]
    # Heuristic: writes `data.add(bitmap)` WITHOUT a preceding compactsize
    # write of `bitmap.len`.
    check "data.add(bitmap)" in bin
    # Look for absence of a compact-size write of `bitmap.len`:
    check "bitmap.len" notin bin or
          "data.add(byte(bitmap.len" notin bin

  test "G15 BUG-7: outs vector emitted with NO CompactSize count prefix":
    let bin =
      restSrc[restSrc.find("of rfBinary:", restSrc.find("handleRestGetUtxos")) ..
              restSrc.find("of rfHex:", restSrc.find("handleRestGetUtxos"))]
    # The outs-loop is `for (height, output) in utxos:` directly after
    # bitmap; no count prefix before the loop.
    check "for (height, output) in utxos:" in bin
    check "utxos.len" notin bin or
          "byte(utxos.len" notin bin

  test "G15 BUG-7: bitmap layout — LSB-first within byte (matches Core)":
    ## Cross-impl: Core uses `bitmap[i/8] |= ((uint8_t)hit) << (i % 8);`.
    ## Nimrod uses `bitmap[i div 8] = bitmap[i div 8] or
    ##              byte(1 shl (i mod 8))`. Same direction. NOT a bug —
    ## this gate is a PRESENT check distinct from BUG-7.
    let body =
      restSrc[restSrc.find("handleRestGetUtxos") ..
              restSrc.find("handleRestMempoolInfo")]
    check "1 shl (i mod 8)" in body

# ---------------------------------------------------------------------------
# G16 — mempoolminfee / minrelaytxfee 1000× too small (BUG-8, P1)
# ---------------------------------------------------------------------------
suite "W141 G16 — mempool fee-rate units (BUG-8)":

  test "G16 BUG-8 (FIXED): source divides sat/vB by 1e5 (correct), not 1e8":
    ## sat/vB × 1000 = sat/kvB; sat/kvB / 1e8 = BTC/kvB, i.e. sat/vB / 1e5.
    ## The rest.nim mempool-info handler uses the correct divisor and reads
    ## the live mp.minFeeRate field (already coupled to the real floor), so
    ## after the fee-floor honesty fix it emits 0.1/1e5 = 0.00000100 BTC.
    ## Source line 773: `let minFee = rest.mempool.minFeeRate / 100000.0`
    let infoBlock =
      restSrc[restSrc.find("handleRestMempoolInfo") ..
              restSrc.find("handleRestMempoolContents")]
    check "/ 100000.0"    in infoBlock        # correct divisor present
    check "/ 100000000.0" notin infoBlock     # wrong (1000x-too-small) divisor absent

  test "G16 BUG-8: rest mempool info reads live mp.minFeeRate (coupled, not hardcoded)":
    ## The display tracks the real admission floor instead of a literal — a
    ## future floor change can never make the rest display drift.
    let infoBlock =
      restSrc[restSrc.find("handleRestMempoolInfo") ..
              restSrc.find("handleRestMempoolContents")]
    check "rest.mempool.minFeeRate" in infoBlock

# ---------------------------------------------------------------------------
# G17 — mempool/contents.json verbose + mempool_sequence params (BUG-9, P1)
# ---------------------------------------------------------------------------
suite "W141 G17 — mempool/contents.json query params (BUG-9)":

  test "G17 BUG-9: handleRestMempoolContents takes no query params":
    let sig =
      restSrc[restSrc.find("proc handleRestMempoolContents*") ..
              restSrc.find("\n# ===", restSrc.find("proc handleRestMempoolContents*"))]
    # Single-arg signature: (rest: RestServer) — no query string param.
    check sig.startsWith("proc handleRestMempoolContents*(rest: RestServer)")
    check "verbose"          notin sig
    check "mempool_sequence" notin sig

  test "G17 BUG-9: nimrod source has no 'verbose' or 'mempool_sequence' anywhere":
    ## Coarser than a per-route slice — Core's rest.cpp:799-823 calls
    ## `req->GetQueryParameter("verbose")` and `"mempool_sequence"`.
    ## Nimrod's REST source has neither identifier in any of its
    ## handlers, parser, or router.
    check "verbose"          notin restSrc
    check "mempool_sequence" notin restSrc

# ---------------------------------------------------------------------------
# G18 — mempool/contents.json synth ancestor/descendant + sat fees (BUG-10/11)
# ---------------------------------------------------------------------------
suite "W141 G18 — mempool/contents.json fake DAG + sat-denominated fees":

  test "G18 BUG-10: descendantcount/ancestorcount hardcoded to 1":
    let body =
      restSrc[restSrc.find("handleRestMempoolContents") ..
              restSrc.find("# ============================================================================\n# Block filter")]
    check "\"descendantcount\": 1" in body
    check "\"ancestorcount\": 1"   in body
    # No mempool DAG walk:
    check "getDescendants"  notin body
    check "getAncestors"    notin body

  test "G18 BUG-11: descendantfees / ancestorfees emitted as int sat (Core: BTC float)":
    let body =
      restSrc[restSrc.find("handleRestMempoolContents") ..
              restSrc.find("# ============================================================================\n# Block filter")]
    # int64(entry.fee) used directly — sat not BTC.
    check "\"descendantfees\": int64(entry.fee)" in body
    check "\"ancestorfees\": int64(entry.ancestorFee)" in body

# ---------------------------------------------------------------------------
# G19 — /rest/block JSON missing versionHex/mediantime/difficulty (BUG-12)
# ---------------------------------------------------------------------------
suite "W141 G19 — block JSON shape (BUG-12)":

  test "G19 BUG-12: block JSON missing versionHex":
    let body =
      restSrc[restSrc.find("proc handleRestBlock*(rest: RestServer") ..
              restSrc.find("proc handleRestBlockNoTxDetails*")]
    check "versionHex" notin body

  test "G19 BUG-12: block JSON missing mediantime":
    let body =
      restSrc[restSrc.find("proc handleRestBlock*(rest: RestServer") ..
              restSrc.find("proc handleRestBlockNoTxDetails*")]
    check "mediantime" notin body

  test "G19 BUG-12: block JSON missing difficulty":
    let body =
      restSrc[restSrc.find("proc handleRestBlock*(rest: RestServer") ..
              restSrc.find("proc handleRestBlockNoTxDetails*")]
    check "\"difficulty\":" notin body

  test "G19 BUG-12: block JSON missing chainwork":
    let body =
      restSrc[restSrc.find("proc handleRestBlock*(rest: RestServer") ..
              restSrc.find("proc handleRestBlockNoTxDetails*")]
    check "chainwork" notin body

# ---------------------------------------------------------------------------
# G20 — /rest/headers 1-segment + ?count=N form (BUG-13, P2)
# ---------------------------------------------------------------------------
suite "W141 G20 — /rest/headers new form (BUG-13)":

  test "G20 BUG-13: handleRestHeaders requires >=2 segments (no 1-segment fallback)":
    let body =
      restSrc[restSrc.find("proc handleRestHeaders*") ..
              restSrc.find("proc handleRestBlockHashByHeight*")]
    # Looks for path.split('/') then `if parts.len < 2`. Core 28+ also
    # accepts parts.len == 1 with ?count=N.
    check "parts.len < 2" in body
    # `parts.len == 1` branch absent:
    check "parts.len == 1" notin body

  test "G20 BUG-13: no ?count= query parse in handleRestHeaders":
    let body =
      restSrc[restSrc.find("proc handleRestHeaders*") ..
              restSrc.find("proc handleRestBlockHashByHeight*")]
    check "?count" notin body
    check "queryCount" notin body

# ---------------------------------------------------------------------------
# G21 — /rest/spenttxouts endpoint (BUG-14, P2)
# ---------------------------------------------------------------------------
suite "W141 G21 — /rest/spenttxouts endpoint (BUG-14)":

  test "G21 BUG-14: no spenttxouts handler in rest.nim":
    check "handleRestSpentTxOuts" notin restSrc
    check "spenttxouts"           notin restSrc
    check "SerializeBlockUndo"    notin restSrc

# ---------------------------------------------------------------------------
# G22 — parseDataFormat case-sensitivity (BUG-15, P3)
# ---------------------------------------------------------------------------
suite "W141 G22 — parseDataFormat suffix case (BUG-15)":

  test "G22 BUG-15: nimrod toLowerAscii's the suffix (Core is case-sensitive)":
    var p = "abc.JSON"
    let rf = parseDataFormat(p, "abc.JSON")
    # Nimrod accepts .JSON as rfJson:
    check rf == rfJson
    check p == "abc"

  test "G22 BUG-15: Core would return UNDEF on uppercase suffix":
    ## This test pins the divergence — when Core sees ".JSON" the
    ## byte-compare against {"bin","hex","json"} fails and it
    ## returns RESTResponseFormat::UNDEF (rest.cpp:143-148).
    ## We leave a forward-regression comment here so a future
    ## "match Core strictness" wave can flip the assertion.
    var p = "abc.HEX"
    let rf = parseDataFormat(p, "abc.HEX")
    check rf == rfHex          # nimrod's current behaviour
    # Forward-regression note: after a hypothetical FIX-86 that
    # tightens parseDataFormat to byte-match, this should become
    # `check rf == rfUndef`.

  test "G22 BUG-15: source calls toLowerAscii on suffix":
    let body =
      restSrc[restSrc.find("proc parseDataFormat*") ..
              restSrc.find("proc availableFormatsString*")]
    check ".toLowerAscii" in body

# ---------------------------------------------------------------------------
# G23 — REST listener bind hardcoded (BUG-16, P1)
# ---------------------------------------------------------------------------
suite "W141 G23 — REST listener bind (BUG-16)":

  test "G23 BUG-16: listener bound to 127.0.0.1 with no override":
    check "initTAddress(\"127.0.0.1\", Port(rest.port))" in restSrc

  test "G23 BUG-16: no --restbind / --rpcbind / --rpcallowip in CLI":
    check "restbind"     notin nimrodSrc
    check "rpcbind"      notin nimrodSrc
    check "rpcallowip"   notin nimrodSrc

# ---------------------------------------------------------------------------
# G24 — CheckWarmup absent on REST endpoints (BUG-17, P1)
# ---------------------------------------------------------------------------
suite "W141 G24 — warmup check absent (BUG-17)":

  test "G24 BUG-17: no checkWarmup / isInWarmup / inWarmup helper":
    check "checkWarmup"      notin restSrc
    check "CheckWarmup"      notin restSrc
    check "isInWarmup"       notin restSrc
    check "RPCIsInWarmup"    notin restSrc

  test "G24 BUG-17: no Http503 'temporarily unavailable' branch in handlers":
    # Http503 is declared as enum value but no handler returns it
    # in the warmup-style path.
    check "Service temporarily unavailable" notin restSrc

# ---------------------------------------------------------------------------
# G25 — Access-Control-Allow-Origin auto-added (BUG-18, P3)
# ---------------------------------------------------------------------------
suite "W141 G25 — CORS wildcard auto-added (BUG-18)":

  test "G25 BUG-18: formatHttpResponse hardcodes ACAO:* (Core does not)":
    let body =
      restSrc[restSrc.find("proc formatHttpResponse") ..
              restSrc.find("proc processStream")]
    check "Access-Control-Allow-Origin: *" in body

  test "G25 BUG-18: no toggle for CORS off":
    check "cors"              notin restSrc
    check "allowOrigin"       notin restSrc
    check "allow-origin"      notin restSrc

# ---------------------------------------------------------------------------
# G26 — Coinbase detection per-input (BUG-19, P1)
# ---------------------------------------------------------------------------
suite "W141 G26 — coinbase detection (BUG-19)":

  test "G26 BUG-19: coinbase classified per-input, not per-tx":
    ## Core IsCoinBase() returns `vin.size() == 1 && vin[0].prevout.IsNull()`.
    ## Nimrod walks `for j, inp in tx.inputs:` and classifies each input,
    ## so a hypothetical 2-input tx with input[0].prevout==null would
    ## yield a vin array with one "coinbase" entry and one normal entry.
    let body =
      restSrc[restSrc.find("# Add vin array") ..
              restSrc.find("# Add vout array")]
    check "for j, inp in tx.inputs:" in body
    check "let isCoinbase = inp.prevOut.txid ==" in body
    # No tx-level guard `tx.inputs.len == 1`:
    check "tx.inputs.len == 1" notin body

# ---------------------------------------------------------------------------
# G27 — Pruned-block reporting absent (BUG-20, P2)
# ---------------------------------------------------------------------------
suite "W141 G27 — pruned-block reporting (BUG-20)":

  test "G27 BUG-20: no BLOCK_HAVE_DATA / pruned-aware 404 message":
    let body =
      restSrc[restSrc.find("proc handleRestBlock*(rest: RestServer") ..
              restSrc.find("proc handleRestBlockNoTxDetails*")]
    check "BLOCK_HAVE_DATA"      notin body
    check "not available (pruned" notin body
    check "isBlockPruned"         notin body
    # Single 404 path with generic message:
    check "not found" in body

# ---------------------------------------------------------------------------
# G28 — -blocknotify=<cmd> not implemented (BUG-21, P2)
# ---------------------------------------------------------------------------
suite "W141 G28 — -blocknotify CLI surface (BUG-21)":

  test "G28 BUG-21: no -blocknotify / blockNotify in nimrod.nim":
    check "blocknotify" notin nimrodSrc
    check "blockNotify" notin nimrodSrc

  test "G28 BUG-21: no runCommand-style helper in any src file":
    ## Cross-impl preventative — note distinct from `runCommand` in
    ## the CLI dispatcher (nimrod.nim:2452 — that one runs nimrod
    ## subcommands, not external shell commands; trivially distinct
    ## from Core's runCommand). Search for shell-exec primitives.
    check "execShellCmd"     notin restSrc
    check "execShellCmd"     notin zmqSrc
    check "execCmd"          notin restSrc
    check "execCmd"          notin zmqSrc
    check "osproc.startProcess" notin restSrc
    check "osproc.startProcess" notin zmqSrc

# ---------------------------------------------------------------------------
# G29 — -walletnotify and -alertnotify not implemented (BUG-22 / BUG-23, P2)
# ---------------------------------------------------------------------------
suite "W141 G29 — -walletnotify / -alertnotify surface (BUG-22 + BUG-23)":

  test "G29 BUG-22: no -walletnotify / walletNotify in nimrod.nim":
    check "walletnotify" notin nimrodSrc
    check "walletNotify" notin nimrodSrc

  test "G29 BUG-23: no -alertnotify / alertNotify in nimrod.nim":
    check "alertnotify" notin nimrodSrc
    check "alertNotify" notin nimrodSrc

  test "G29 (universal pattern): if added, MUST avoid shell-injection":
    ## Universal advisory (W141 META). This test passes today
    ## (no implementation), but pins the contract for the future
    ## implementer.
    ##
    ## Required pattern:
    ##   1. Use startProcess(args = @[...], options = {}) — never
    ##      execShellCmd / execCmd, unless behind an explicit
    ##      --notify-shell opt-in.
    ##   2. Substitute %s / %w / %b / %h ONLY into the args vector,
    ##      never into a pre-shell-quoted string.
    ##   3. For %w (wallet name): require shell-escape mirroring
    ##      Core's common/system.cpp ShellEscape (single-quote
    ##      wrapping with embedded-single-quote handling).
    check true   # PRESENT — pin contract.

# ---------------------------------------------------------------------------
# G30 — ZMQ module wired into node + getzmqnotifications RPC (BUG-24/25/26)
# ---------------------------------------------------------------------------
suite "W141 G30 — ZMQ wiring + getzmqnotifications RPC (BUG-24/25/26)":

  test "G30 BUG-24: src/rpc/zmq is NEVER imported anywhere in production":
    ## The whole 579-LOC module is orphaned. Tests import it. The
    ## CLI / connect-tip / mempool paths do not.
    check "import ./rpc/zmq"      notin nimrodSrc
    check "import ../rpc/zmq"     notin nimrodSrc
    check "import rpc/zmq"        notin nimrodSrc
    check "import ./../rpc/zmq"   notin nimrodSrc
    # And no field on any state type:
    check "ZmqNotificationInterface" notin nimrodSrc

  test "G30 BUG-24: no -zmqpubhashblock / -zmqpubhashtx / -zmqpubsequence in CLI":
    check "zmqpubhashblock" notin nimrodSrc
    check "zmqpubhashtx"    notin nimrodSrc
    check "zmqpubrawblock"  notin nimrodSrc
    check "zmqpubrawtx"     notin nimrodSrc
    check "zmqpubsequence"  notin nimrodSrc

  test "G30 BUG-24: no notifyTip / notifyBlockConnected / notifyMempoolAccept call sites":
    check "notifyTip(" notin nimrodSrc
    check "notifyBlockConnected("  notin nimrodSrc
    check "notifyBlockDisconnected(" notin nimrodSrc
    check "notifyMempoolAccept(" notin nimrodSrc
    check "notifyMempoolRemove(" notin nimrodSrc

  test "G30 BUG-25: getActiveNotifiers returns tuple seq (cosmetic-vs-Core)":
    ## Core list<const CZMQAbstractNotifier*>; nimrod
    ## seq[tuple[notifierType: string, address: string, hwm: int]].
    ## Shape is fine for the JSON output but per-notifier object
    ## state (sequence, last error) is opaque.
    let sig =
      zmqSrc[zmqSrc.find("proc getActiveNotifiers*") ..
             zmqSrc.find("\n# ===", zmqSrc.find("proc getActiveNotifiers*"))]
    check "tuple[" in sig
    check "notifierType: string" in sig

  test "G30 BUG-26: getzmqnotifications RPC plumbed but rpc.zmq field never assigned":
    ## CORRECTION on audit framing: server.nim DOES define
    ## `handleGetZmqNotifications` (line ~3338), dispatch
    ## `"getzmqnotifications"` (line ~8329), and an `rpc.zmq` field
    ## (line ~51). **However**, the `newRpcServer` constructor
    ## (line ~105-130) does NOT take a `zmq:` parameter and does NOT
    ## assign the field — so `rpc.zmq` is always `nil` at runtime
    ## and the handler returns an empty array unconditionally.
    ##
    ## This is the SAME "plumb-gate-then-flip" cross-wave pattern
    ## as FIX-71→FIX-81/FIX-82 (compact-filter activation gap).
    check "handleGetZmqNotifications" in serverSrc        # handler exists
    check "getzmqnotifications"       in serverSrc        # dispatched
    check "zmq*: ZmqNotificationInterface" in serverSrc   # field declared
    # But the constructor body has no zmq assignment:
    let ctor =
      serverSrc[serverSrc.find("proc newRpcServer*(") ..
                serverSrc.find("proc isBlockSubmissionPaused*")]
    check "zmq:"  notin ctor      # no parameter
    check "zmq =" notin ctor      # no field assignment after construction
    check "zmq," notin ctor       # not a positional arg
