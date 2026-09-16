# Changelog

## v1.0.2 — 2026-09-16

- 59fee59 fix: getMedianTimePastFromChain median of last min(11,n) times (BIP113)
- d828ff2 fix: params.nim campaign parser typo 'andentry' -> 'and entry' (compile break)
- 22a60b8 fix: graft campaign base_tail_headers so snapshot-boot header-sync starts at the base
- b3b428c fix: T2 R5 probe parity (error codes, PSBT, missing RPCs)
- 82e48b3 fix: stop tracking the phaseb verifyscript shim ELF
- 7029b72 fix: activate loadtxoutset onto the live chainstate
- 263b1af test: triage the 50 failures 2e819ea made visible


## v1.0.2 — 2026-09-16

- fix: `getMedianTimePastFromChain` is again the BIP113 median of the last
  min(11, n) timestamps. 22a60b8 routed every lookup through
  `getHeaderByHeight`, which returns none when `hashes`/`byHash` are empty,
  so an 11-header window of times 100..1100 returned 0 instead of 600.
  Hash-index lookup is used only when `hashes` covers the height (snapshot
  holes); otherwise `headers[h]` is read directly.

## v1.0.2 — 2026-09-16

Changes since `v1.0.0`:

- fix: T2 R5 probe parity (error codes, PSBT object outputs, missing RPCs).
  Control: `nim c -r tests/test_t2_r5_parity.nim`.
- fix: stop tracking `tools/phaseb_verifyscript_shim` (compiled ELF).
  Every rebuild rewrote the binary so `git status` never stayed clean
  (DIRTY-TREE skip). Source remains; rebuild with `nimble build_shim`.
- test: triage the 50 aggregate failures 2e819ea made visible.
  node-bug (1, fixed): JSON-RPC accepted GET as POST — now 405, request
  lines require an HTTP/ token (Core httprpc.cpp). Control: reverting
  parseHttpRequestLine to startsWith("GET") fails "GET-User-Time header
  is not a request line" and G28.
  test-bug (45, flipped): misbehavior PR #25974, RFC1918 netgroup,
  BIP155 wire IDs, assumeutxo count, arity -1, stale W-audit xfails,
  empty-vin decoder raise, etc.
  gap-skip (4): -rpcauth HMAC (G4), JSON-RPC 2.0 notifications (G13),
  assumeUTXO height-not-chainwork (G17), W139 audit doc not in this
  repo. `nim c -r tests/test_all.nim`: 5621 run, 5560 OK, 0 FAILED.
- 3f89f2e docs: say the cited paths are private before the claims that rest on them
- 2e819ea fix: run all the tests, and stop the summary reporting green while they fail
- a3317e8 feat: announce when assumevalid is disabled
- 533c963 feat: HASHHOG_UNSAFE_SNAPSHOT_HEIGHT — accept an un-anchored UTXO snapshot

