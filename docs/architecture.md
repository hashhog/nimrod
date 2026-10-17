# Architecture

nimrod is one Nim program, `src/nimrod.nim`, compiled with ARC memory management and
threads on. Networking and RPC use the chronos async library. Hashing, signatures and
storage go through C libraries over FFI: libsecp256k1 for ECDSA and Schnorr, RocksDB for
the chainstate, SQLite for wallets.

## Moving parts

| Part | Where | Notes |
|---|---|---|
| Entry point | `src/nimrod.nim` | Flag parsing, startup, the main loop, signal handling, shutdown, block import, metrics endpoint. |
| Types and serialization | `src/primitives/` | Transactions, blocks, 256-bit integers, CompactSize and witness encoding. |
| Crypto | `src/crypto/` | SHA-256 (with a SHA-NI path in `sha256_shani.c`), RIPEMD-160, secp256k1 bindings, base58, bech32/bech32m, MuHash, SipHash, ChaCha20-Poly1305 and HKDF for BIP-324, minisketch. |
| Consensus | `src/consensus/` | Network parameters (`params.nim`), block and transaction checks (`validation.nim`), difficulty (`pow.nim`), BIP-9 deployments (`versionbits.nim`), the assume-valid gate (`assumevalid.nim`). |
| Script | `src/script/interpreter.nim` | The script interpreter and sighash for legacy, BIP-143 and BIP-341/342. |
| Storage | `src/storage/` | `chainstate.nim` connects and disconnects blocks against the UTXO set; `db.nim` wraps RocksDB column families; `utxo_cache.nim` is the layered coins cache; `undo.nim` serializes undo data; `pruner.nim`; `snapshot.nim` reads and writes assumeUTXO snapshots; `indexes/` holds the tx, block-filter, coin-stats and spender indexes. |
| P2P | `src/network/` | `peer.nim` (connections, v1 and BIP-324 v2 transport), `peermanager.nim` (outbound selection, eviction, bans), `sync.nim` (headers-first sync and parallel block download), `headerssync.nim` (PRESYNC/REDOWNLOAD low-work header defence), `addrman.nim`, `compact_blocks.nim` (BIP-152), `erlay.nim`, `proxy.nim` (SOCKS5, Tor, I2P). |
| Mempool | `src/mempool/` | Acceptance and policy (`mempool.nim`, `standard.nim`), cluster linearization (`cluster.nim`), package relay (`package.nim`), orphans, `mempool.dat` persistence. |
| Mining | `src/mining/` | `getblocktemplate` construction and fee estimation. |
| RPC | `src/rpc/` | `server.nim` is the JSON-RPC server and every handler; it runs on its own OS thread (`rpc_thread.nim`) so long validation work does not block it. `rest.nim` is the REST server, `zmq.nim` the ZMQ message encoding. |
| Wallet | `src/wallet/` | Keys and transactions (`wallet.nim`), multi-wallet management (`manager.nim`), SQLite storage, descriptors and miniscript, PSBT, coin selection (branch-and-bound and knapsack), fee bumping, encryption (`crypter.nim`), BIP-78 PayJoin. |
| Performance | `src/perf/` | Parallel script verification pool and signature cache. |

## Storage layout

All chain data for a network is in one RocksDB database at
`<datadir>/<network>/chainstate/`, in column families: block index, block bodies, undo
data, the UTXO set, chain state and the indexes. Block bodies are stored in RocksDB, not
in `blk*.dat` files; the `blocks/` directory is created but stays empty. Each wallet is
a SQLite file at `<datadir>/<network>/wallets/<name>/wallet.db`.

## Threads

The main thread runs the chronos event loop for P2P and block connection. The RPC server
and the REST server each run their own thread and event loop; RPC handlers that touch
chain state take a chain lock first. Script checks during block connection fan out to a
worker pool sized by `--par`. A background thread reconciles wallets with the chain at
startup.

## Tests

`tests/` holds one `test_*.nim` file per area; `tests/test_all.nim` imports all of them
into one binary and fails the build if a file is neither imported nor explicitly
excluded. `tests/data/` holds small vector files (BIP-32, addresses, blocks, a short
script file); the full `script_tests.json` is read from a Bitcoin Core checkout at
`../bitcoin-core` (see [status.md](status.md#test-suite)).
