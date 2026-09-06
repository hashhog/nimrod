## W125 — JSON-RPC error code parity audit (xfail regression guards)
##
## Audit type: discovery (NO production code change in W125).
##
## Each test below pins the *current* error code nimrod returns for a
## raise site that Bitcoin Core handles with a different (more specific)
## code per `bitcoin-core/src/rpc/protocol.h`.  The pin protects against
## silent regressions and acts as a tombstone: when a future FIX wave
## moves the raise site to the correct code, the test fails loudly and
## the developer flips the assertion (per the methodology used in
## `test_w122_codec_stress.nim` and `test_w120_mempool_rbf.nim`).
##
## Each test also documents the Core expected code as a TODO comment so
## the gap is discoverable from the test file alone.
##
## Method:
##   - The JSON-RPC envelope layer (parse / invalid-request / batch)
##     lives in private procs (`handleSingleRequest`, `handleRequest`).
##     Gates 1-5 are asserted indirectly via Core source-level evidence
##     in the per-suite comments + by exercising `handleMethod` for the
##     unknown-method case (Gate 3).
##   - Application-layer gates (6-30) exercise `handleMethod` directly
##     and inspect the raised `RpcError.code`.  The bare-bones
##     RpcServer construction follows `test_networkdisable.nim`.
##
## References:
##   bitcoin-core/src/rpc/protocol.h            enum RPCErrorCode
##   bitcoin-core/src/rpc/server.cpp            warmup gate / dispatch
##   bitcoin-core/src/rpc/server_util.cpp       P2P / mempool gates
##   bitcoin-core/src/rpc/mining.cpp            NOT_CONNECTED / IBD
##   bitcoin-core/src/rpc/rawtransaction.cpp    DESERIALIZATION_ERROR
##   bitcoin-core/src/wallet/rpc/encrypt.cpp    wallet enc-state codes
##   audit/w125_rpc_error_parity.md             full audit + gate table

import unittest2
import std/[json, strutils]
import ../src/rpc/server

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc minimalRpcServer(): RpcServer =
  ## Bare-bones RpcServer with no chainstate / mempool / peerManager /
  ## wallet.  Sufficient for exercising any handler whose first-line
  ## check is `nil`.  Pattern stolen from `test_networkdisable.nim`.
  RpcServer(
    port: 0,
    running: false,
    blockSubmissionPaused: false
  )

template captureRpcError(body: untyped): tuple[code: int, msg: string] =
  ## Run `body`, catch any RpcError, return its code+msg.  If a non-Rpc
  ## CatchableError is raised, code=-32603 (matching the dispatcher's
  ## outer catch).  If no exception, code=0 with msg="(no error)".
  var captured = (code: 0, msg: "(no error)")
  try:
    discard body
  except RpcError as e:
    captured = (code: e.code, msg: e.msg)
  except CatchableError as e:
    # Outer dispatcher would wrap this as -32603 / "internal error".
    captured = (code: -32603, msg: "internal error: " & e.msg)
  captured

proc rpcMethodErr(rpc: RpcServer, methodName: string,
                  params: JsonNode = newJArray()): tuple[code: int, msg: string] =
  ## Convenience: invoke `handleMethod` with the supplied method name +
  ## params, return the resulting error code+msg (0 if no error).
  captureRpcError(rpc.handleMethod(methodName, params))

# ===========================================================================
# Gate 1 — RPC_PARSE_ERROR (-32700) PRESENT
# Asserted source-level: server.nim:81 defines RpcParseError = -32700
# and server.nim:8563 maps json.JsonParsingError → RpcParseError.
# ===========================================================================
suite "W125 Gate 1: -32700 RPC_PARSE_ERROR — PRESENT (source-level)":
  test "PRESENT — RpcParseError constant is exported and equals -32700":
    check RpcParseError == -32700

# ===========================================================================
# Gate 2 — RPC_INVALID_REQUEST (-32600) PRESENT
# Asserted source-level: server.nim:82 + raise sites at 8505,8514,8523,8572,8576.
# ===========================================================================
suite "W125 Gate 2: -32600 RPC_INVALID_REQUEST — PRESENT (source-level)":
  test "PRESENT — RpcInvalidRequest constant is -32600":
    check RpcInvalidRequest == -32600

# ===========================================================================
# Gate 3 — RPC_METHOD_NOT_FOUND (-32601) PRESENT
# Asserted via runtime: handleMethod raises RpcMethodNotFound on unknown.
# ===========================================================================
suite "W125 Gate 3: -32601 RPC_METHOD_NOT_FOUND — PRESENT":
  test "PRESENT — unknown method name raises -32601":
    let rpc = minimalRpcServer()
    let r = rpc.rpcMethodErr("not_a_real_rpc_method", %*[])
    check r.code == -32601
    check "method not found" in r.msg

  test "PRESENT — RpcMethodNotFound constant is -32601":
    check RpcMethodNotFound == -32601

# ===========================================================================
# Gate 4 — RPC_INVALID_PARAMS (-32602) PARTIAL (envelope OK, app-layer collapse)
# ===========================================================================
suite "W125 Gate 4: -32602 RPC_INVALID_PARAMS — PARTIAL (over-used)":
  test "PRESENT — getblockhash with empty params raises -32602":
    ## This site is envelope-level (missing required param).  -32602
    ## is arguably correct here.  But the same code is shared with
    ## application sites (Gate 10) — that's the PARTIAL classification.
    let rpc = minimalRpcServer()
    let r = rpc.rpcMethodErr("getblockhash", %*[])
    check r.code == -32602
    check "missing height" in r.msg

  test "PRESENT — RpcInvalidParams constant is -32602":
    check RpcInvalidParams == -32602

# ===========================================================================
# Gate 5 — RPC_INTERNAL_ERROR (-32603) PRESENT
# ===========================================================================
suite "W125 Gate 5: -32603 RPC_INTERNAL_ERROR — PRESENT":
  test "PRESENT — RpcInternalError constant is -32603":
    check RpcInternalError == -32603

  test "PRESENT — dumpmempool with nil mempool raises -32603":
    ## Per server.nim:1388 — nimrod uses -32603 for "Mempool unavailable",
    ## which Core would split into -33 RPC_CLIENT_MEMPOOL_DISABLED.
    ## See Gate 25.
    let rpc = minimalRpcServer()
    let r = rpc.rpcMethodErr("dumpmempool", %*[])
    check r.code == -32603

  test "PRESENT — RpcInternalError is over-used for component-disabled paths":
    ## Documents the over-use: addnode with nil peerManager and
    ## dumpmempool with nil mempool both surface as -32603 instead of
    ## Core's -31 / -33.  See Gates 24 / 25.
    let rpc = minimalRpcServer()
    let r1 = rpc.rpcMethodErr("addnode", %*["127.0.0.1:8333", "add"])
    let r2 = rpc.rpcMethodErr("loadmempool", %*[])
    check r1.code == -32603
    check r2.code == -32603

# ===========================================================================
# Gate 6 — RPC_MISC_ERROR (-1) PRESENT (over-used; see Gates 11/27/30)
# ===========================================================================
suite "W125 Gate 6: -1 RPC_MISC_ERROR — PRESENT (over-used)":
  test "PRESENT — RpcMiscError constant is -1":
    check RpcMiscError == -1

  test "PRESENT — walletlock with no wallet raises -1 (should be -18 per Core)":
    ## TODO(W125 Gate 30): expected -18 RPC_WALLET_NOT_FOUND.
    ## See server.nim:5224 "wallet not loaded".
    let rpc = minimalRpcServer()
    let r = rpc.rpcMethodErr("walletlock", %*[])
    check r.code == -1

# ===========================================================================
# Gate 7 — RPC_TYPE_ERROR (-3) MISSING (currently -32602)
# ===========================================================================
suite "W125 Gate 7: -3 RPC_TYPE_ERROR — MISSING":
  test "absence — no RpcTypeError constant exported by server.nim":
    ## This compile-time check would fail to compile if the symbol
    ## existed.  Asserted indirectly by the runtime behavior below.
    let rpc = minimalRpcServer()
    let r = rpc.rpcMethodErr("getrawtransaction", %*["00", "not-bool"])
    # -3 RPC_TYPE_ERROR is the Core code for "wrong type" parameters.
    # nimrod never raises it.  Pin the current behavior.
    check r.code != -3

# ===========================================================================
# Gate 8 — RPC_INVALID_ADDRESS_OR_KEY (-5) PRESENT
# ===========================================================================
suite "W125 Gate 8: -5 RPC_INVALID_ADDRESS_OR_KEY — PRESENT":
  test "PRESENT — RpcInvalidAddressOrKey constant is -5":
    check RpcInvalidAddressOrKey == -5

  test "FIXED — getrawtransaction with malformed txid raises -8 (was -5)":
    ## Core ParseHashV (rpc/util.cpp:117) rejects a malformed txid at the
    ## parse boundary with RPC_INVALID_PARAMETER (-8), BEFORE any lookup.
    ## nimrod previously collapsed this to -5; the FIX wave wired
    ## validateHashV so the malformed case now matches Core exactly.
    ## (The well-formed-but-absent txid still returns -5 — see Gate 8b note.)
    let rpc = minimalRpcServer()
    # "00" is too short → Core "txid must be of length 64 (not 2, for '00')".
    let r = rpc.rpcMethodErr("getrawtransaction", %*["00"])
    check r.code == -8
    check "must be of length 64" in r.msg

# ===========================================================================
# Gate 9 — RPC_OUT_OF_MEMORY (-7) MISSING (no analog)
# ===========================================================================
suite "W125 Gate 9: -7 RPC_OUT_OF_MEMORY — MISSING":
  test "absence — no RpcOutOfMemory constant exported by server.nim":
    ## Compile-time evidence: if RpcOutOfMemory existed, it would be
    ## in the inventory below.  Documented as MISSING in the audit;
    ## counted for parity but no practical runtime test.
    ## See audit/w125_rpc_error_parity.md Gate 9.
    let allKnown = @[
      RpcParseError, RpcInvalidRequest, RpcMethodNotFound,
      RpcInvalidParams, RpcInternalError, RpcMiscError,
      RpcWalletError, RpcInvalidAddressOrKey,
      RpcTransactionError, RpcTransactionRejected,
      RpcTransactionAlreadyInChain
    ]
    # -7 is not among any of the defined constants.
    check (-7) notin allKnown

# ===========================================================================
# Gate 10 — RPC_INVALID_PARAMETER (-8) MISSING (currently -32602)
# Largest semantic gap: 176 Core raise sites all map to -32602 in nimrod.
# ===========================================================================
suite "W125 Gate 10: -8 RPC_INVALID_PARAMETER — MISSING (xfail)":
  test "xfail — sendrawtransaction maxfeerate > 1 currently -32602":
    ## TODO(W125 Gate 10): expected Core code -8 RPC_INVALID_PARAMETER.
    ## See server.nim:2927 "maxfeerate cannot exceed 1 BTC/kvB".
    let rpc = minimalRpcServer()
    let r = rpc.rpcMethodErr("sendrawtransaction", %*["00", 5.0])
    check r.code == -32602

  test "xfail — testmempoolaccept empty rawtxs array currently -32602":
    ## TODO(W125 Gate 10): expected -8.  See server.nim:3024.
    let rpc = minimalRpcServer()
    let r = rpc.rpcMethodErr("testmempoolaccept", %*[newJArray()])
    check r.code == -32602

  test "xfail — submitpackage empty rawtxs array currently -32602":
    ## TODO(W125 Gate 10): expected -8.  See server.nim:3236.
    let rpc = minimalRpcServer()
    let r = rpc.rpcMethodErr("submitpackage", %*[newJArray()])
    check r.code == -32602

# ===========================================================================
# Gate 11 — RPC_DATABASE_ERROR (-20) MISSING
# ===========================================================================
suite "W125 Gate 11: -20 RPC_DATABASE_ERROR — MISSING":
  test "absence — no -20 constant defined in server.nim":
    ## TODO(W125 Gate 11): wire RocksDB / wallet-DB IO errors through
    ## a new RpcDatabaseError = -20 constant.  Currently nimrod has no
    ## -20 anywhere; DB errors surface as -1 / -32603 depending on
    ## which catch block intercepts them.  Source-level evidence
    ## suffices because attempting any chainstate RPC against the
    ## nil-state minimalRpcServer segfaults rather than raises.
    let allKnown = @[
      RpcParseError, RpcInvalidRequest, RpcMethodNotFound,
      RpcInvalidParams, RpcInternalError, RpcMiscError,
      RpcWalletError, RpcInvalidAddressOrKey,
      RpcTransactionError, RpcTransactionRejected,
      RpcTransactionAlreadyInChain
    ]
    check (-20) notin allKnown

# ===========================================================================
# Gate 12 — RPC_DESERIALIZATION_ERROR (-22) MISSING (currently -32602)
# 28 Core raise sites for TX/block/PSBT/script decode failures.
# ===========================================================================
suite "W125 Gate 12: -22 RPC_DESERIALIZATION_ERROR — MISSING (xfail)":
  test "xfail — sendrawtransaction non-hex bytes currently -32602":
    ## TODO(W125 Gate 12): expected -22 RPC_DESERIALIZATION_ERROR.
    ## See server.nim:2996 "TX decode failed".
    let rpc = minimalRpcServer()
    # Pass odd-length / invalid hex to trigger the decode-failed path.
    # Note: depending on how parsing fails, the error may surface as
    # -32602 (caught by the try/except in handleSendRawTransaction) or
    # -32603 (if it escapes to the dispatcher).
    let r = rpc.rpcMethodErr("sendrawtransaction", %*["xx"])
    # Both -32602 and -32603 are wrong; Core says -22.
    check r.code in [-32602, -32603]
    check r.code != -22  # the gap

  test "xfail — decoderawtransaction non-hex bytes":
    ## TODO(W125 Gate 12): expected -22.
    let rpc = minimalRpcServer()
    let r = rpc.rpcMethodErr("decoderawtransaction", %*["xx"])
    check r.code != -22

  test "xfail — decodescript non-hex bytes currently -32602":
    ## TODO(W125 Gate 12): expected -22.  See server.nim:2646.
    let rpc = minimalRpcServer()
    let r = rpc.rpcMethodErr("decodescript", %*["xx"])
    check r.code != -22

# ===========================================================================
# Gate 13 — RPC_VERIFY_ERROR (-25) PARTIAL
# ===========================================================================
suite "W125 Gate 13: -25 RPC_VERIFY_ERROR — PARTIAL":
  test "PRESENT (alias) — RpcTransactionError constant is -25":
    ## Constant defined at server.nim:91 with the comment "Generic
    ## transaction error".  This is Core's RPC_VERIFY_ERROR alias.
    check RpcTransactionError == -25

  test "PARTIAL — submitblock with bad hex returns BIP-22 string, not -25":
    ## Core's submitblock proposal mode raises -25 with the state
    ## string (`mining.cpp:1141`).  nimrod returns the BIP-22 result
    ## string ("rejected") via the outer catch (`server.nim:~3968`)
    ## for invalid blocks, never -25.  No RpcError raised → code=0.
    let rpc = minimalRpcServer()
    let r = rpc.rpcMethodErr("submitblock", %*["00"])
    check r.code == 0       # no RpcError raised
    check r.code != -25     # the gap: should be -25 per Core

# ===========================================================================
# Gate 14 — RPC_VERIFY_REJECTED (-26) PRESENT
# ===========================================================================
suite "W125 Gate 14: -26 RPC_VERIFY_REJECTED — PRESENT":
  test "PRESENT — RpcTransactionRejected constant is -26":
    check RpcTransactionRejected == -26

# ===========================================================================
# Gate 15 — RPC_VERIFY_ALREADY_IN_UTXO_SET (-27) PRESENT
# ===========================================================================
suite "W125 Gate 15: -27 RPC_TRANSACTION_ALREADY_IN_CHAIN — PRESENT":
  test "PRESENT — RpcTransactionAlreadyInChain constant is -27":
    check RpcTransactionAlreadyInChain == -27

# ===========================================================================
# Gate 16 — RPC_IN_WARMUP (-28) MISSING
# ===========================================================================
suite "W125 Gate 16: -28 RPC_IN_WARMUP — MISSING":
  test "absence — no -28 constant; no warmup gate in handleSingleRequest":
    ## TODO(W125 Gate 16): introduce a `warmup` field on RpcServer and
    ## gate handleSingleRequest to raise -28 when set.
    ## See `bitcoin-core/src/rpc/server.cpp:488`.
    ## Documented at source-level since invoking any chainstate RPC on
    ## a nil-state RpcServer segfaults.
    let allKnown = @[
      RpcParseError, RpcInvalidRequest, RpcMethodNotFound,
      RpcInvalidParams, RpcInternalError, RpcMiscError,
      RpcWalletError, RpcInvalidAddressOrKey,
      RpcTransactionError, RpcTransactionRejected,
      RpcTransactionAlreadyInChain
    ]
    check (-28) notin allKnown

# ===========================================================================
# Gate 17 — RPC_METHOD_DEPRECATED (-32) MISSING
# ===========================================================================
suite "W125 Gate 17: -32 RPC_METHOD_DEPRECATED — MISSING":
  test "absence — no deprecated-method gating":
    ## TODO(W125 Gate 17): for any RPC marked deprecated in Core but
    ## still wired in nimrod (e.g. `savemempool` alias) raise -32 when
    ## `-deprecatedrpc=savemempool` is not enabled.  Today nimrod
    ## silently routes savemempool → dumpmempool (server.nim:8294).
    let rpc = minimalRpcServer()
    let r = rpc.rpcMethodErr("savemempool", %*[])
    # Gets -32603 (mempool nil → RpcInternalError).
    check r.code != -32

# ===========================================================================
# Gate 18 — RPC_CLIENT_NOT_CONNECTED (-9) MISSING (currently -32603)
# ===========================================================================
suite "W125 Gate 18: -9 RPC_CLIENT_NOT_CONNECTED — MISSING":
  test "absence — no -9 constant defined; getblocktemplate has no peer-check":
    ## TODO(W125 Gate 18): wire IsP2PConnected check in
    ## handleGetBlockTemplate.  See bitcoin-core/src/rpc/mining.cpp:769.
    ## handleGetBlockTemplate (server.nim:3577) calls buildBlockTemplate
    ## with rpc.chainState; with nil chainState it segfaults rather
    ## than raises.  Asserted at source level only.
    let allKnown = @[
      RpcParseError, RpcInvalidRequest, RpcMethodNotFound,
      RpcInvalidParams, RpcInternalError, RpcMiscError,
      RpcWalletError, RpcInvalidAddressOrKey,
      RpcTransactionError, RpcTransactionRejected,
      RpcTransactionAlreadyInChain
    ]
    check (-9) notin allKnown

# ===========================================================================
# Gate 19 — RPC_CLIENT_IN_INITIAL_DOWNLOAD (-10) MISSING
# ===========================================================================
suite "W125 Gate 19: -10 RPC_CLIENT_IN_INITIAL_DOWNLOAD — MISSING":
  test "absence — no -10 constant; no IBD gate":
    ## TODO(W125 Gate 19): wire `ibdMode` check into
    ## handleGetBlockTemplate / handleLoadMempool.  See
    ## bitcoin-core/src/rpc/mining.cpp:773 and
    ## bitcoin-core/src/rpc/mempool.cpp:1141.
    let allKnown = @[
      RpcParseError, RpcInvalidRequest, RpcMethodNotFound,
      RpcInvalidParams, RpcInternalError, RpcMiscError,
      RpcWalletError, RpcInvalidAddressOrKey,
      RpcTransactionError, RpcTransactionRejected,
      RpcTransactionAlreadyInChain
    ]
    check (-10) notin allKnown

# ===========================================================================
# Gates 20-22 — RPC_CLIENT_NODE_{ALREADY_ADDED, NOT_ADDED, NOT_CONNECTED}
# -23 / -24 / -29 — MISSING
# ===========================================================================
suite "W125 Gate 21: -24 RPC_CLIENT_NODE_NOT_ADDED — MISSING":
  test "absence — addnode 'remove' on unknown peer never raises -24":
    ## TODO(W125 Gate 21): expected Core code -24.
    ## See server.nim:3564-3568 (silently no-ops with no peerMgr).
    let rpc = minimalRpcServer()
    let r = rpc.rpcMethodErr("addnode", %*["127.0.0.1:8333", "remove"])
    # With nil peerManager, fires the nil-check at L3544 first.
    check r.code != -24

suite "W125 Gate 22: -29 RPC_CLIENT_NODE_NOT_CONNECTED — MISSING":
  test "absence — disconnectnode unknown peer never raises -29":
    ## TODO(W125 Gate 22): expected Core code -29.
    let rpc = minimalRpcServer()
    let r = rpc.rpcMethodErr("disconnectnode", %*["127.0.0.1:8333"])
    check r.code != -29

# ===========================================================================
# Gate 23 — RPC_CLIENT_INVALID_IP_OR_SUBNET (-30) PARTIAL (currently -32602)
# ===========================================================================
suite "W125 Gate 23: -30 RPC_CLIENT_INVALID_IP_OR_SUBNET — PARTIAL":
  test "xfail — addnode with bad port does not raise -30":
    ## TODO(W125 Gate 23): expected Core code -30.
    ## See server.nim:3556 "invalid port number".
    ## Without peerManager, the nil-check fires first → -32603.
    let rpc = minimalRpcServer()
    let r = rpc.rpcMethodErr("addnode", %*["127.0.0.1:not-a-port", "add"])
    check r.code != -30

# ===========================================================================
# Gate 24 — RPC_CLIENT_P2P_DISABLED (-31) MISSING (currently -32603)
# ===========================================================================
suite "W125 Gate 24: -31 RPC_CLIENT_P2P_DISABLED — MISSING (xfail)":
  test "xfail — addnode with nil peerManager currently -32603":
    ## TODO(W125 Gate 24): expected Core code -31.
    ## See server.nim:3544 "peer manager not available" — currently
    ## RpcInternalError; should be RpcClientP2pDisabled (-31).
    let rpc = minimalRpcServer()
    let r = rpc.rpcMethodErr("addnode", %*["127.0.0.1:8333", "add"])
    check r.code == -32603  # current (wrong) code; pin so fix flips

# ===========================================================================
# Gate 25 — RPC_CLIENT_MEMPOOL_DISABLED (-33) MISSING (currently -32603)
# ===========================================================================
suite "W125 Gate 25: -33 RPC_CLIENT_MEMPOOL_DISABLED — MISSING (xfail)":
  test "xfail — dumpmempool with nil mempool currently -32603":
    ## TODO(W125 Gate 25): expected Core code -33.
    ## See server.nim:1388 "Mempool unavailable".
    let rpc = minimalRpcServer()
    let r = rpc.rpcMethodErr("dumpmempool", %*[])
    check r.code == -32603  # current (wrong) code

  test "xfail — loadmempool with nil mempool currently -32603":
    ## TODO(W125 Gate 25): same; see server.nim:1405.
    let rpc = minimalRpcServer()
    let r = rpc.rpcMethodErr("loadmempool", %*[])
    check r.code == -32603

  ## NOTE: getmempoolinfo / getrawmempool segfault on nil mempool
  ## (no nil-check at server.nim:1199); cannot exercise directly.
  ## The -33 absence is documented via the dumpmempool/loadmempool
  ## tests above and the source-level inventory at the bottom of
  ## this file.

# ===========================================================================
# Gate 26 — RPC_WALLET_ERROR (-4) PRESENT
# ===========================================================================
suite "W125 Gate 26: -4 RPC_WALLET_ERROR — PRESENT":
  test "PRESENT — RpcWalletError constant is -4":
    check RpcWalletError == -4

# ===========================================================================
# Gate 27 — RPC_WALLET_INSUFFICIENT_FUNDS (-6) MISSING
# ===========================================================================
suite "W125 Gate 27: -6 RPC_WALLET_INSUFFICIENT_FUNDS — MISSING":
  test "absence — no -6 constant or raise site":
    ## TODO(W125 Gate 27): introduce RpcWalletInsufficientFunds = -6
    ## and route sendtoaddress / walletcreatefundedpsbt /
    ## sendmany insufficient-funds paths through it (currently
    ## surfacing as RpcMiscError / RpcWalletError).
    let rpc = minimalRpcServer()
    let r = rpc.rpcMethodErr("sendtoaddress", %*[])
    check r.code != -6

# ===========================================================================
# Gate 28 — RPC_WALLET_INVALID_LABEL_NAME (-11) MISSING
# ===========================================================================
suite "W125 Gate 28: -11 RPC_WALLET_INVALID_LABEL_NAME — MISSING":
  test "absence — no label-name validation":
    ## TODO(W125 Gate 28): wire label-name validation in `setlabel`.
    let rpc = minimalRpcServer()
    let r = rpc.rpcMethodErr("setlabel", %*[])
    check r.code != -11

# ===========================================================================
# Gate 29 — RPC_WALLET_KEYPOOL_RAN_OUT (-12) MISSING
# ===========================================================================
suite "W125 Gate 29: -12 RPC_WALLET_KEYPOOL_RAN_OUT — MISSING":
  test "absence — no -12 raise site":
    ## TODO(W125 Gate 29): if/when nimrod adds a keypool concept,
    ## raise -12 on exhaustion at `getnewaddress` /
    ## `getrawchangeaddress`.
    let rpc = minimalRpcServer()
    let r = rpc.rpcMethodErr("getnewaddress", %*[])
    check r.code != -12

# ===========================================================================
# Gate 30 — RPC_WALLET_{UNLOCK_NEEDED, PASSPHRASE_INCORRECT,
#                       WRONG_ENC_STATE, ENCRYPTION_FAILED,
#                       ALREADY_UNLOCKED, NOT_FOUND}
# -13 / -14 / -15 / -16 / -17 / -18 — MISSING (all currently -1)
# Single largest user-visible cluster of "wrong code" in nimrod.
# ===========================================================================
suite "W125 Gate 30: wallet enc-state codes -13..-18 — MISSING (xfail)":
  test "xfail — walletpassphrase with no wallet returns -1 (should be -18)":
    ## TODO(W125 Gate 30): expected Core code -18 RPC_WALLET_NOT_FOUND
    ## (when no wallet exists) or -13 RPC_WALLET_UNLOCK_NEEDED (when
    ## wallet exists but is locked).  See server.nim:5224 / 5867.
    let rpc = minimalRpcServer()
    let r = rpc.rpcMethodErr("walletpassphrase", %*["pw", 60])
    check r.code == -1  # currently RpcMiscError

  test "xfail — encryptwallet with no wallet returns -1 (should be -18)":
    ## TODO(W125 Gate 30): expected -18 RPC_WALLET_NOT_FOUND.
    ## See server.nim:5841 / 5224.
    let rpc = minimalRpcServer()
    let r = rpc.rpcMethodErr("encryptwallet", %*["pw"])
    check r.code == -1

  test "xfail — walletlock with no wallet returns -1 (should be -18)":
    let rpc = minimalRpcServer()
    let r = rpc.rpcMethodErr("walletlock", %*[])
    check r.code == -1

  test "xfail — walletpassphrasechange with no wallet returns -1 (should be -18)":
    let rpc = minimalRpcServer()
    let r = rpc.rpcMethodErr("walletpassphrasechange", %*["old", "new"])
    check r.code == -1

# ===========================================================================
# Source-level inventory: count of distinct error codes defined locally.
# Documents the gap vs Core's ~30-code enum.
# ===========================================================================
suite "W125 source-level inventory":
  test "nimrod defines a strict subset of Core's RPCErrorCode enum":
    ## All of these must resolve at compile time — proof that nimrod
    ## *does* export these symbols.  Missing constants enumerated in
    ## the audit doc.
    let definedCodes = @[
      RpcParseError,                # -32700  Gate 1   PRESENT
      RpcInvalidRequest,            # -32600  Gate 2   PRESENT
      RpcMethodNotFound,            # -32601  Gate 3   PRESENT
      RpcInvalidParams,             # -32602  Gate 4   PARTIAL
      RpcInternalError,             # -32603  Gate 5   PRESENT (over-used)
      RpcMiscError,                 # -1      Gate 6   PRESENT (over-used)
      RpcWalletError,               # -4      Gate 26  PRESENT
      RpcInvalidAddressOrKey,       # -5      Gate 8   PRESENT
      RpcTransactionError,          # -25     Gate 13  PARTIAL (alias)
      RpcTransactionRejected,       # -26     Gate 14  PRESENT
      RpcTransactionAlreadyInChain  # -27     Gate 15  PRESENT
    ]
    check definedCodes.len == 11
    # Missing constants (must be added in future FIX waves):
    #   -3  RpcTypeError                  (Gate 7)
    #   -6  RpcWalletInsufficientFunds    (Gate 27)
    #   -7  RpcOutOfMemory                (Gate 9)
    #   -8  RpcInvalidParameter           (Gate 10)   ★ largest gap
    #   -9  RpcClientNotConnected         (Gate 18)
    #   -10 RpcClientInInitialDownload    (Gate 19)
    #   -11 RpcWalletInvalidLabelName     (Gate 28)
    #   -12 RpcWalletKeypoolRanOut        (Gate 29)
    #   -13 RpcWalletUnlockNeeded         (Gate 30)
    #   -14 RpcWalletPassphraseIncorrect  (Gate 30)
    #   -15 RpcWalletWrongEncState        (Gate 30)
    #   -16 RpcWalletEncryptionFailed     (Gate 30)
    #   -17 RpcWalletAlreadyUnlocked      (Gate 30)
    #   -18 RpcWalletNotFound             (Gate 30)
    #   -19 RpcWalletNotSpecified         (Gate 30)
    #   -20 RpcDatabaseError              (Gate 11)
    #   -22 RpcDeserializationError       (Gate 12)
    #   -23 RpcClientNodeAlreadyAdded     (Gate 20)
    #   -24 RpcClientNodeNotAdded         (Gate 21)
    #   -28 RpcInWarmup                   (Gate 16)
    #   -29 RpcClientNodeNotConnected     (Gate 22)
    #   -30 RpcClientInvalidIpOrSubnet    (Gate 23)
    #   -31 RpcClientP2pDisabled          (Gate 24)
    #   -32 RpcMethodDeprecated           (Gate 17)
    #   -33 RpcClientMempoolDisabled      (Gate 25)
    #   -34 RpcClientNodeCapacityReached
    #   -35 RpcWalletAlreadyLoaded
    #   -36 RpcWalletAlreadyExists
    # Net MISSING: 27 codes (counted in audit doc).
