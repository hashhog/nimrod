# Running nimrod

```
nimrod [options] <command> [args]
```

`./bin/nimrod --help` prints the usage. This page is taken from the option parser in
`src/nimrod.nim` (`parseArgs`), which accepts a few flags that `--help` does not list;
they are marked below.

Options take `--name=value` or `--name:value`. Boolean flags also accept `=1`/`=0`.
Core's single-dash `-par=N` is accepted.

## Commands

| Command | What it does |
|---|---|
| `start` | Run the node (the default when no command is given). |
| `stop` | Ask a running node to shut down. |
| `getinfo` | Print chain, height, best block, difficulty and chain work. |
| `getblock <hash>` | Print a block. |
| `sendrawtransaction <hex>` | Submit a raw transaction. |
| `getbalance`, `getnewaddress`, `sendtoaddress <addr> <amount>` | Wallet calls. |
| `help`, `version` | Same as `--help`, `--version`. |

The client commands talk to `127.0.0.1:<rpcport>` and authenticate only with
`--rpcuser`/`--rpcpassword`; they do not read the cookie file. Pass the same network,
port and credentials you started the node with:

```bash
./bin/nimrod --regtest --datadir="$DATADIR" --rpcuser=alice --rpcpassword=secret start > "$DATADIR/node.log" 2>&1 &
sleep 3
./bin/nimrod --regtest --rpcuser=alice --rpcpassword=secret getinfo
./bin/nimrod --regtest --rpcuser=alice --rpcpassword=secret stop
```

For everything else use the JSON-RPC interface ([rpc.md](rpc.md)).

## Networks

| Flag | Network | P2P | RPC |
|---|---|---|---|
| (default), `--network=mainnet` | mainnet | 8333 | 8332 |
| `--network=testnet4` | testnet4 | 48333 | 48332 |
| `--network=testnet3`, `--testnet` | testnet3 | 18333 | 18332 |
| `--network=regtest`, `--regtest` | regtest | 18444 | 18443 |

The network-specific port defaults apply only if `--port`/`--rpcport` were not given
earlier on the command line, so put the network flag first. Signet parameters exist in
the code but `--network=signet` is rejected with `Unknown network: signet`.

## Options

### General

| Flag | Default | Meaning |
|---|---|---|
| `-d`, `--datadir=DIR` | `~/.nimrod` | Data directory. |
| `-n`, `--network=NET` | `mainnet` | `mainnet`, `testnet3`, `testnet4`, `regtest`. |
| `--conf=PATH` | `<datadir>/nimrod.conf` | Config file (see below). |
| `-l`, `--loglevel=LEVEL` | `info` | `trace`, `debug`, `info`, `warn`, `error`. |
| `--debug=CAT[,CAT]` | none | Extra debug categories (`net`, `p2p`, `sync`, `rpc`, ...; `all`). Repeatable. |
| `--daemon` | off | Fork and detach. |
| `--pid=PATH` | `<datadir>/nimrod.pid` | PID file. |
| `--printtoconsole` | off | Keep stdout/stderr live under `--daemon`. |
| `--debuglogfile=PATH` | see Logging | Log file. |
| `--ready-fd=N` | off | Write a newline to file descriptor N once startup is done (for supervisors). |
| `-h`, `--help`; `-v`, `--version` | | |

### Chain and validation

| Flag | Default | Meaning |
|---|---|---|
| `--assumevalid=0`, `--noassumevalid` | assume-valid on | Verify every script from genesis. Other values keep the built-in assume-valid block; an alternate hash cannot be given. |
| `--prune=MiB` | `0` (off) | `1` = manual pruning with `pruneblockchain` only; `>= 550` = keep about that many MiB of blocks. 2-549 is rejected. |
| `--dbcache=MiB` | `0` (built-in, about 2 GiB) | UTXO cache budget, 0-1048576. Raises the cache, never lowers it below the default. |
| `--maxmempool=MB` | `300` | Mempool memory budget in megabytes. The pool is trimmed (worst chunk first) when Bitcoin Core's `DynamicMemoryUsage` estimate of it exceeds this; that estimate is what `getmempoolinfo` reports as `usage`. |
| `--par=N`, `--verify-threads=N` | `0` (auto) | Script-check threads, as Core's `-par`: 0 = auto, 1 = serial, < 0 leaves that many cores free. |
| `--reindex` | off | Wipe the chainstate before starting and re-download from peers. |
| `--load-snapshot=PATH` | none | Load a Core-format UTXO snapshot (assumeUTXO) before starting. |
| `--import-blocks=DIR` | none | Not in `--help`. Import blocks from `blk*.dat` files in DIR (Core's XOR-obfuscated files are detected), or from framed stdin with `-`, then exit. |
| `--ibd-flush-interval=N` | `0` (2000) | Flush to disk every N blocks during initial sync, 0-5000. |
| `--txindex` | | Accepted for Core compatibility; the transaction index is always kept. |
| `--blockfilterindex[=basic]` | off | Keep the BIP-158 basic filter index. |
| `--coinstatsindex` | off | Keep per-height UTXO-set statistics, so `gettxoutsetinfo` can answer for a past height. |
| `--txospenderindex` | off | Not in `--help`. Index spent outpoints for `gettxspendingprevout` on confirmed spends. |

### P2P

| Flag | Default | Meaning |
|---|---|---|
| `-p`, `--port=PORT` | per network | P2P listen port. |
| `--bind=ADDR` | `0.0.0.0` and `::` | Listen address. Repeatable. |
| `--listen[=0\|1]`, `--nolisten` | on | Accept inbound connections. |
| `--maxconnections=N` | `125` | Peer limit. |
| `--connect=IP[:PORT]` | none | Connect only to these peers (repeatable); disables DNS seeds and automatic outbound. `--connect=0` clears. |
| `--dnsseed=0`, `--nodnsseed` | seeds on | Do not query DNS seeds. |
| `--externalip=IP[:PORT]` | none | Address to advertise. Repeatable or comma-separated. Implies `--discover=0` unless set. |
| `--discover[=0\|1]`, `--nodiscover` | on | Learn our address from peers. |
| `--proxy=HOST:PORT` | none | SOCKS5 proxy for outbound IPv4/IPv6 (and `.onion` if `--onion` is unset). |
| `--onion=HOST:PORT` | none | Tor SOCKS5 proxy for `.onion`. |
| `--i2psam=HOST:PORT` | none | I2P SAM bridge. |
| `--cjdnsreachable` | off | Allow outbound to CJDNS (`fc00::/8`). |
| `--asmap=FILE` | none | ASMap file for AS-based peer bucketing. |
| `--peerblockfilters` | off | Serve BIP-157 filters to peers. Needs `--blockfilterindex`. |

### RPC, REST and metrics

| Flag | Default | Meaning |
|---|---|---|
| `--rpcport=PORT` | per network | JSON-RPC port, bound to `127.0.0.1`. |
| `--rpcuser=USER`, `--rpcpassword=PASS` | none | Basic-auth credentials, in addition to the cookie. |
| `--norpc` | RPC on | Disable the RPC server. |
| `--rest` | off | Read-only REST server on `127.0.0.1`. |
| `--restport=PORT` | `rpcport + 1000` | REST port. |
| `--rpc-tls-cert=PATH`, `--rpc-tls-key=PATH` | none | Serve REST over TLS. Both or neither; the key must be unencrypted PKCS#8 PEM. |
| `--metricsport=PORT` | `9332` | Not in `--help`. Prometheus endpoint on `0.0.0.0`; `0` disables it. |

## Config file

The parser reads `<datadir>/nimrod.conf` (or `--conf=PATH`): one `key=value` per line,
`#` comments, the same key names as the long flags. **In this version the values it
reads are not applied**: `parseArgs` loads the file into a copy of the configuration
and then discards it, so only command-line flags take effect. You can see this by
putting `regtest=1` in the file and starting the node: it starts on mainnet. Use flags
until this is fixed. `config/nimrod.conf` and `config.example.toml` in the repository
are examples from earlier versions and are not read by anything.

## Environment variables

| Variable | Effect |
|---|---|
| `NIMROD_BIP324_V2_OUTBOUND=0` | Do not try BIP-324 v2 transport on outbound connections (default: try v2, fall back to v1). |
| `NIMROD_BLOCK_DOWNLOAD_TIMEOUT_SECS` | Override the per-block download timeout. |
| `NIMROD_SEND_STALL_TIMEOUT_MS` | Override the peer send-stall timeout. |
| `NIMROD_PEER_BLOOM_FILTERS=1` | Answer BIP-35 `mempool` requests. NODE_BLOOM is never advertised. |

## Data directory

Everything for a network lives in `<datadir>/<network>/`, mainnet included:

```
<datadir>/nimrod.pid          PID file (removed on clean shutdown)
<datadir>/<network>/.cookie   RPC cookie, mode 0600, removed on clean shutdown
<datadir>/<network>/chainstate/   RocksDB: block index, block bodies, undo data, UTXO set, indexes
<datadir>/<network>/blocks/   created at startup; block bodies are stored in RocksDB
<datadir>/<network>/wallets/<name>/   one directory per wallet (wallet.db is SQLite)
<datadir>/<network>/peers.dat, mempool.dat, fee_estimates.json   written on shutdown
<datadir>/<network>/debug.log    log file under --daemon
```

## Resources

A full mainnet node keeps every block. Plan for at least 1 TB of fast disk (SSD or
NVMe), or prune with `--prune=550` or more. The default UTXO cache tops out around
2 GiB; with `--dbcache` raised, initial sync is faster and RSS grows accordingly. Give the
machine at least 8 GB of RAM. Initial sync with `--assumevalid=0` checks every script
and takes days.

## Logging

Logs go to stdout. Under `--daemon` they go to `<datadir>/<network>/debug.log`, or to
`--debuglogfile`. `SIGHUP` reopens the log file, for log rotation. `SIGINT` and `SIGTERM`
shut the node down cleanly, as does the `stop` RPC.

## Metrics

`http://<host>:9332/metrics` serves Prometheus text format: block height, peer count,
mempool size and similar gauges. If the port is taken, the node logs
`metrics server bind failed; metrics disabled` and keeps running.

```bash
curl -s http://127.0.0.1:9332/metrics | head
```
