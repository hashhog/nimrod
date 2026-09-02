# Changelog

## v1.0.0 (unreleased)

Changes since `v0.1.0-rc1`:

- b04da6f docs: LICENSE, toolchain versions in README (release hygiene)
- baaebf8 fix(rpc): implement the dispatcher arity check every handler already defers to
- 2543d7a fix(net): one thread-local RNG instead of reseeding a shared global per call
- 75f8f85 fix(test): consensus vector suite could not find its vectors
- 03aa707 test: fix the 17 stale nimrod tests — suite is 2169/2169 green
- 1ccc80e chore: stop tracking compiled test binaries; ignore them by pattern
- 134e5a0 fix(rpc): buried deployment "active" is DeploymentActiveAfter, not ActiveAt
- c3f7576 test: run-all-tests.sh — nimble test covers 110 of 222 test files; this shows the rest
- 62a042a fix: one MinBlocksToKeep, not three — unblocks the test aggregate (#93)
- 71dbcd9 fix(rpc): the integer conversion runs before the lookup, and setban/disconnectnode match Core
- 4f5388c fix(rpc): estimatesmartfee validates estimate_mode and uses Core's conf_target error
- d86678b fix(rpc): read integer arguments at Core's width, and honour the ones we read
- b100d6f fix(rpc): createrawtransaction ignored the `version` argument
- a5aeaf5 fix(rpc): getblockhash rejects an out-of-domain height instead of answering genesis
- ee8dca3 fix(rpc): submitblock decode failure reports Core's token, not the decoder's own text
- 6042704 fix(rpc): createrawtransaction non-numeric sequence is ignored; fractional sequence is -1
- 8f3caad fix(rpc): createrawtransaction rejects replaceable=true contradicted by its sequences
- 44a08f6 fix(rpc): createrawtransaction rejects an out-of-int32 vout instead of truncating it to 0
- 4686224 test: reorg CONNECT path with an intra-block tx chain (#64)
- 36170b1 feat(shim): retarget-window context — real difficulty verification at boundaries
- 6d5a558 fix(storage): nil-db guard for getBlockIndex + terminate the shim ancestor walk
- 9f25915 fix(storage): getBlockHashByHeight guards a nil db handle — corpus-replay SIGSEGV
- 7439221 fix(consensus): chainstate block work is EXACT 2^256/(target+1), not quantised to one bit (#53)
- 23cc47c fix(p2p): BlockDownloader reverts batch assignment on failed getdata; getaddr reply uses spawnSafe (#74)
- fccf4ae refactor(p2p): delete two dead degenerate locator builders (second-implementation traps)
- 3e96bfa fix(sync): header tip could fall behind the chain, and stored bodies never connected

