# nimrod

A Bitcoin full node written from scratch in Nim. One of the ten [hashhog](https://github.com/hashhog) nodes.

> **Experimental.** hashhog nodes are independent re-implementations of Bitcoin Core for research and testing. Do not use them with real funds.

## Status

| Area | State |
|---|---|
| Mainnet validation | Validated mainnet from genesis to height 958,794 with assumevalid off and matched Bitcoin Core's `gettxoutsetinfo` `hash_serialized_3` there (`29692050…6e7af0`, 166,180,925 coins). How to reproduce: [docs/status.md](docs/status.md). |
| Consensus vectors | Passes every entry of Bitcoin Core's `script_tests.json` (1,222 of 1,222; the rest are comments). See [docs/status.md](docs/status.md#cores-script-vectors). |
| RPC | 146 JSON-RPC methods modelled on Core's, plus a read-only REST interface. Known differences in [docs/rpc.md](docs/rpc.md). |
| P2P | Headers-first sync, parallel block download, BIP-324 v2 transport, addrv2, SOCKS5/Tor/I2P outbound. Compact blocks are partial; no BIP-37 bloom filters. |
| Wallet | HD wallet (BIP-32/44/49/84/86), descriptors, PSBT, multi-wallet, SQLite storage. Not audited. |
| Known limitations | The config file is read but its values are not applied; no signet. See [docs/status.md](docs/status.md#known-limitations). |

Last updated: 2026-10-17.

## Quick start

Needs Nim 2.2 (tested with 2.2.8 and nimble 0.20.1; install with
[choosenim](https://github.com/nim-lang/choosenim)), a C compiler, and the RocksDB,
libsecp256k1 and SQLite development packages. On Debian/Ubuntu:

```bash
sudo apt-get install -y build-essential git librocksdb-dev libsecp256k1-dev libsqlite3-dev libsnappy-dev liblz4-dev zlib1g-dev
git clone https://github.com/hashhog/nimrod.git
cd nimrod
nimble setup -y
nimble build -d:release -y
./bin/nimrod --version
```

Start a regtest node in a throwaway data directory and make an RPC call:

```bash
export DATADIR=$(mktemp -d)
./bin/nimrod --regtest --datadir="$DATADIR" start > "$DATADIR/node.log" 2>&1 &
sleep 3
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" -d '{"method":"getblockchaininfo","params":[]}' http://127.0.0.1:18443/
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" -d '{"method":"stop","params":[]}' http://127.0.0.1:18443/
```

More detail, including build variants and a reproducible-build recipe, is in
[docs/building.md](docs/building.md).

## Running

```bash
./bin/nimrod --network=mainnet  --datadir="$HOME/.nimrod" start
./bin/nimrod --network=testnet4 --datadir="$HOME/.nimrod" start
./bin/nimrod --network=testnet3 --datadir="$HOME/.nimrod" start
./bin/nimrod --network=regtest  --datadir="$HOME/.nimrod" start
```

Every network, mainnet included, gets its own subdirectory of the data directory
(`$DATADIR/mainnet`, `$DATADIR/regtest`, ...). Signet is not selectable.

| Network | P2P port | RPC port |
|---|---|---|
| mainnet | 8333 | 8332 |
| testnet4 | 48333 | 48332 |
| testnet3 | 18333 | 18332 |
| regtest | 18444 | 18443 |

RPC binds to `127.0.0.1`. P2P listens on `0.0.0.0` and `::`. A Prometheus metrics
endpoint listens on `0.0.0.0:9332` (`--metricsport=0` turns it off; a busy port only
disables metrics).

A full mainnet node keeps every block: plan for at least 1 TB of fast disk, or use
`--prune=550` (or larger, in MiB) to keep only recent blocks. `--dbcache=<MiB>` raises
the UTXO cache above its default of about 2 GiB; give the machine at least 8 GB of RAM.
`--assumevalid=0` checks every script from genesis instead of trusting the built-in
assume-valid block.

All flags, the data directory layout and logging are in [docs/running.md](docs/running.md).

## RPC

nimrod aims to match Bitcoin Core's JSON-RPC interface: same method names, parameters
and result shapes. It accepts HTTP Basic auth with either the `.cookie` file written to
`<datadir>/<network>/` at startup or `--rpcuser`/`--rpcpassword`:

```bash
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" \
  -d '{"jsonrpc":"1.0","id":1,"method":"getblockcount","params":[]}' http://127.0.0.1:18443/
```

The method list and known differences from Core are in [docs/rpc.md](docs/rpc.md).

## Development

```bash
git clone --depth 1 --branch v31.1 https://github.com/bitcoin/bitcoin.git ../bitcoin-core
nimble test
```

The suite reads Core's test vectors from `../bitcoin-core`. `nimble test` compiles and
runs `tests/test_all.nim`, which imports every `tests/test_*.nim` file (see
[docs/status.md](docs/status.md#test-suite) for what it covers).

```
src/nimrod.nim      entry point, CLI flags, node startup and shutdown
src/consensus/      chain parameters, validation, PoW, assumevalid, BIP-9
src/script/         script interpreter and sighash
src/storage/        RocksDB chainstate, UTXO cache, undo data, pruning, indexes
src/network/        peers, addrman, header and block sync, BIP-324, compact blocks
src/mempool/        mempool policy, cluster linearization, packages, orphans
src/mining/         block templates, fee estimation
src/rpc/            JSON-RPC, REST, ZMQ
src/wallet/         HD wallet, descriptors, PSBT, coin selection
tests/              test suite and vector files (tests/data/)
```

The full map is in [docs/architecture.md](docs/architecture.md). See
[CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Security

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
