# nimrod proof bundle

A skeptical Bitcoin engineer should be able to check this node without
trusting a narrative. This directory is that check: every claim below
names a file in this directory, and `bash proof/verify.sh` re-checks
those files (and re-runs the in-repo controls).

It claims **only what the included files show.**

## How to check

From the nimrod repository root:

```
bash proof/check-pin.sh
bash proof/verify.sh
```

`check-pin.sh` is the attested-binary closure: it exits 0 only if
`claims.json` / `provenance.txt` agree and, when a pin or live unit is
observable, that sha256 is the recorded one. `verify.sh` re-checks
every claim in `claims.json` against a file here, refuses a
snapshot-booted lineage, re-runs the in-repo R5 help-parity test, and
calls `check-pin.sh`. After every promote run `bash proof/on-promote.sh`
(or `nimble attest_pin`) so the closure cannot go stale. That is a
release step, not a manual afterthought.

Re-running the heavy instruments (from-genesis IBD, full R2 corpus, live
R5 probe) needs the commands in `r4/`, `r1/command.txt`, `r2/command.txt`,
`r5/command.txt`. Those take days / hours / a running node. The files
here are the captured results of those commands.

## What each file proves

### Provenance — `provenance.txt`

The sha256 of the **promoted pin** (the binary actually running), the
commit that pin was built from, and the toolchain (Nim 2.2.8 / nimble
0.20.1). Written by `assemble.sh` via `on-promote.sh`. Enforced by
`check-pin.sh`. **Does not prove** bit-exact reproducible builds across
toolchains — see `REPRODUCIBLE-BUILD.md`. A local `bin/nimrod` rebuild
is not the attested binary.

### R4 from-genesis lineage — `r4/`

TRUST-ANCHOR rule, applied without weakening: a reproduction of C(H)
counts only if the chainstate at H descends from a genesis→H validation
with scripts on (`assumevalid=0`) executed by this node's own validation
code. **Snapshot-booted lineages do not count.**

| file | what it proves | what it does not prove |
|---|---|---|
| `r4/C958794.json` | The commitment: height 958794, bestblock `000000000000000000015eaadd989e4f09ff75b643a128dc7bdf6070431d7d0e`, `hash_serialized_3` `29692050559b8f064a03af9cd605040e71d1d978fa22947c079cc7e5546e7af0`, 166,180,925 coins. | That this tree's binary is the one that built the set. The capture is of a genesis-rig process. |
| `r4/capture.md` | The capture receipt: MATCH at 2026-08-18T22:01:06Z, tip frozen at 958794, no rollback. | Ratification (the receipt said a human still had to append the TRUST-ANCHOR row; that row exists separately). |
| `r4/capture-watch-excerpt.txt` | The watcher log: FROZEN ON ANCHOR → `*** MATCH ***` the same hash. | The UTXO scan transcript (gettxoutsetinfo JSON was not persisted beyond the receipt). |
| `r4/capture-state-marker.txt` | Idempotency marker written on MATCH, containing the same hash. | Anything about later tips. |
| `r4/genesis-unit.service` | The launch command: `--assumevalid=0`, `--connect=127.0.0.1:28620` (capped blk-replay), datadir `/home/work/genesis-ibd/nimrod`, no loadtxoutset. | That a stranger can re-run it without that datadir and the capped feeder. |
| `r4/lineage.log.gz` | The lineage receipt: start at height 0 on Bitcoin's genesis hash `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`, no `loadtxoutset`/`assumeutxo`/`snapshot` lines, flush at height 958794. Uncompressed sha256 is `r4/lineage.log.sha256`. | Blocks after 958794. The log is append-only across restarts of the same datadir; later lines are the frozen-at-anchor hang, not further validation. |
| `r4/lineage-excerpt.txt` | The load-bearing lines of that log, for a reader who does not want to gunzip 107,164 lines. | Completeness — the gzip is the receipt. |
| `r4/av0-250000-ledger.txt` and `r4/av0-250000-ledger.jsonl` | A **separate** AV=0 genesis→250,000 replay: 11 checkpoints, each hash == Core, 6,802,755 txouts at 250,000, `overall=ALL-PASS`. | C(958794). This run records txouts, not `hash_serialized_3`. It is supporting evidence, not the T2 capture. |

### R1 interpreter — `r1/`

Core's script/tx/sighash vectors through nimrod's own `VerifyScript` /
CheckTransaction / legacy SignatureHash.

| file | what it proves | what it does not prove |
|---|---|---|
| `r1/results.json` | script 1217/1217, tx_valid 121/121, tx_invalid 93/93, sighash 500/500, 0 divergences. 5 `script_tests.json` rows fail to assemble before the interpreter runs (CHARTER: 1,936 vectors, 1,931 decided). | Reason-string parity (358 informational reject-reason mismatches on script; decision still correct). |
| `r1/script.txt`, `r1/tx.txt`, `r1/sighash.txt` | The raw harness summaries that `results.json` was taken from. | A stranger's re-run — that is `r1/command.txt`. |

### R2 validator — `r2/`

Adversarial corpus, accept/reject vs live `bitcoind`.

| file | what it proves | what it does not prove |
|---|---|---|
| `r2/results.json` | 365 PASS / 5 FAIL / 0 ERR of the nightly 370-entry sweep (98.6%). All five FAILs are reject-vs-reject with a different reason string. `consensus_splits_accept_vs_reject: 0`. | Error-code / reject-token identity with Core. The five named entries still differ on *why* they reject. |
| `r2/nightly-report-excerpt.txt` | The nightly report row those numbers were copied from. | A clean classifier: the 10-impl report has an accounting gap on split counts; the five nimrod FAIL logs were read directly. |

### R5 operator RPC — `r5/`

| file | what it proves | what it does not prove |
|---|---|---|
| `r5/live-20260917T102316Z.json` | Live lane 2026-09-17T10:23Z: T1 44/46, T2 40/41, one FAIL (`getnetworkhashps` help-parity). T3 is SKIP-REGTEST on this lane. | The pin running that probe is this commit. It is not. |
| `r5/regtest-20260917T080758Z.json` | Regtest lane: T1 1/1, T2 1/1, T3 16/16, 18 methods scored, 0 FAIL. | Wallet behaviour outside the 16-method T3 subset. |
| `r5/t1-before.txt` / `r5/t1-after.txt` | The help-parity FAIL encoded as `tests/test_t1_r5_parity.nim`: 7 OK / 1 FAILED → 8 OK / 0 FAILED after `handleHelp` listed `getnetworkhashps ( nblocks height )`. | A live `r5_probe.py` going green. That needs an operator restart of the mainnet unit, which this run does not do. |
| `r5/scorecard.json` | The numbers above in one place, each pointing at the artifact. | Anything not in those artifacts. |

## What is NOT proven here

- **Tip parity is not consensus evidence.** The live node matching Core's
  tip proves serialization, PoW, headers-first sync and UTXO bookkeeping
  on the assumevalid-skipped prefix. R1/R2/R4 are the consensus proof.
- **Blocks after 958794** have no from-genesis UTXO-hash capture.
- **Snapshot-boot / assumeUTXO activation** is a declared carve-out
  (boot-smoke), not a passing gate. It is also not a substitute for the
  lineage above.
- **Bitcoin Core fullblocktests, stale-block replay, BIP90 asserts,
  bitcoinfuzz.** Not in this bundle.
- **Fund custody.** Do not send money to this node. See `SECURITY.md`.
- **That a stranger can replay the 19-day genesis IBD** without the
  datadir, the capped feeder, and the original binary. They can check
  the log and the capture hash; they cannot cheaply reproduce them.

## TRUST-ANCHOR, applied

A snapshot-booted range (`range-runner.sh` CLOSED rows) is **not** in
this bundle as R4 evidence. Those boots start from a Core-format UTXO
snapshot; counting them as from-genesis would be circular. The R4 files
above are the genesis-rig log + the frozen-at-958794 capture.
