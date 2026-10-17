# Status: how to check it yourself

Each row of the README status table, and how to reproduce it from this repository.

## Test suite

The suite reads Bitcoin Core's script test vectors from a Core source checkout. It looks
for `bitcoin-core/src/test/data/` in the repository root or in a parent directory, so
clone Core next to nimrod first:

```bash
git clone --depth 1 --branch v31.1 https://github.com/bitcoin/bitcoin.git ../bitcoin-core
nimble test
```

Without the checkout the run stops partway with
`FATAL: could not find test vectors 'script_tests.json'` and a non-zero exit.

`nimble test` compiles `tests/test_all.nim`, which imports all 262 `tests/test_*.nim`
files, and runs it. The compile takes about two minutes and the run about three on a
16-core machine. The last lines report the counts and the coverage:

```
[Summary] 6135 tests run (192.1s): 6072 OK, 2 FAILED, 61 SKIPPED

[Coverage] tests/test_*.nim on disk: 262  compiled in: 262  excluded: 0
```

That is the result on `master` as of the date in the README; the two failures are
listed under [Known limitations](#known-limitations). The compiled binary is
`tests/test_all`. Do not pass it command-line options: one test parses the process's
arguments as nimrod flags and stops the run on an unknown one. Set unittest2's output
level through the environment instead. To see each failed or skipped test by name
(skipped tests carry a message naming the gap they pin):

```bash
UNITTEST2_OUTPUT_LVL=VERBOSE ./tests/test_all 2>&1 | grep -aE '^\s+\[(FAILED|SKIPPED)' | head -70
```

## Core's script vectors

`tests/test_script_vectors.nim` runs every entry of Core's
`src/test/data/script_tests.json` (from the checkout above) through nimrod's script
interpreter. To run only that file:

```bash
nim c -r --hints:off tests/test_script_vectors.nim 2>&1 | grep -E 'script_tests.json results|Summary'
```

Expected with Core v31.1:

```
Bitcoin Core script_tests.json script_tests.json results: 1222 passed, 0 failed, 51 skipped, 0 parse errors (113 witness tests included)
```

The skipped entries are the comment lines in the file.

## UTXO-set hash at height 958,794

The UTXO set at a given height has one correct `hash_serialized_3`; at mainnet height
958,794 (block `000000000000000000015eaadd989e4f09ff75b643a128dc7bdf6070431d7d0e`) it is
`29692050559b8f064a03af9cd605040e71d1d978fa22947c079cc7e5546e7af0` over 166,180,925
coins. You can get both numbers from Bitcoin Core with `gettxoutsetinfo` at that height.

nimrod reached that height from genesis with `--assumevalid=0` (every script checked) and
reported the same hash and coin count. To repeat it, sync a mainnet node with
`--assumevalid=0` past 958,794. `gettxoutsetinfo` reports the hash only for the current
tip, as in Core, so roll the tip back with `invalidateblock` on the block at 958,795,
read the hash, then undo it:

```bash
RPC() { curl -s --user "$(cat "$COOKIE")" -d "{\"method\":\"$1\",\"params\":$2}" "$URL"; }
COOKIE=~/.nimrod/mainnet/.cookie URL=http://127.0.0.1:8332/
NEXT=$(RPC getblockhash '[958795]' | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])')
RPC invalidateblock "[\"$NEXT\"]"
RPC gettxoutsetinfo '["hash_serialized_3"]'
RPC reconsiderblock "[\"$NEXT\"]"
```

The same commands work on a regtest node (set `COOKIE`, `URL` and the height to match).
A from-genesis mainnet sync with every script checked takes days.

## RPC

`help` on a running node lists the methods; [rpc.md](rpc.md) lists all 146 dispatched
methods and the known differences from Core. The quick start in the README and the
examples in rpc.md exercise the RPC on regtest.

## Known limitations

- The config file (`nimrod.conf`) is parsed but its values are not applied; use
  command-line flags. See [running.md](running.md#config-file).
- Signet cannot be selected (`--network=signet` exits with `Unknown network`).
- The `nimrod getinfo`/`stop`/... client commands do not read the cookie file; they work
  only with `--rpcuser`/`--rpcpassword`.
- `--version` prints `nimrod v0.1.0` (the version in `nimrod.nimble`), not the release
  version in `CHANGELOG.md`.
- Two tests in the suite fail: "G2 BUG-1 (P0): RPC `stop` is a no-op confession"
  (`tests/test_w124_operator.nim`) and "G2 BUG-2: performHandshake calls
  sendSendHeaders without version/chainwork gate" (`tests/test_w136_relay_flags.nim`).
  Both check the source text for an old bug, and the source has since changed: the `stop`
  RPC now shuts the node down, and `sendheaders` is now sent only to peers with protocol
  version 70012 or later (Core also waits for the peer's chain work; nimrod does not).
- Skipped tests in the suite name gaps against Core. The main groups: BIP-37 bloom
  filters (`filterload`, `merkleblock`) are not implemented; BIP-152 compact block relay
  is partial (no high-bandwidth announce mode, and `getblocktxn` requests are logged but
  not answered); some BIP-340 Schnorr vectors are not covered. The list command above
  shows them all. A skip records a gap when the test was written; check the code before
  relying on one.
- Named RPC parameters work for only 14 wallet methods; 29 methods are missing from
  `help`. See [rpc.md](rpc.md#known-differences-from-core).
- No ZMQ publisher can be configured.
- The wallet has not been audited. Do not hold real funds in it.
