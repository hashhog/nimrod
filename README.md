# nimrod

A Bitcoin full node written from scratch in Nim. Part of the Hashhog project.

## Status — v1.0.0

**Label: "Validated — reproduced Core's UTXO set from genesis with all scripts
verified"** (`receipts/RELEASE-v1.0-SCORECARD.md`, §What each label means). That
label means one specific thing: nimrod connected every mainnet block from block 0
to height 958,794 with its assumevalid gate off, serialized its entire UTXO set,
and produced the byte string
`29692050559b8f064a03af9cd605040e71d1d978fa22947c079cc7e5546e7af0` over
166,180,925 coins — the same value Bitcoin Core's `dumptxoutset` produced at that
height. A single wrong coin anywhere in fifteen years changes that hash — the *capture* is unfakeable. **The lineage under it is not checkable from a clone:** what the ledger row records is height, hash and coin count; that the chain beneath was built from genesis with assumevalid off rests on the row's `lineage receipt` column, and four of the five rows point at logs under `/home/work/genesis-ibd/logs/` — outside any repository and uncommitted — while blockbrew's says only `--commit` (`receipts/TRUST-ANCHOR.md:141-145`). The git
tag `v0.1.0-rc1` (`receipts/RELEASE-v1.0-FREEZE.md`) marks the same bar: `rc` in this
project certifies that reproduction and nothing else
(`receipts/beta1-tag-drafts-2026-08-20.md:23-27`). Neither label certifies wallet
or fund-custody readiness — see `SECURITY.md`.

**Operator RPC parity: 52 of Bitcoin Core's 85.** From the 103-method R5
operator probe run 2026-09-01T18:26:42Z
(`tools/diff-test-artifacts/r5-probe/20260901T182642Z.json`): nimrod 52 PASS /
33 FAIL, Bitcoin Core 85 PASS on the same probe, 18 methods unmeasured
(`SKIP-REGTEST`) for every node including Core. Cite the run, not "the score":
the probe ten minutes earlier
(`tools/diff-test-artifacts/r5-probe/20260901T181552Z.json`) scored nimrod 51
with no deploy in between. **Two** of nimrod's 33 failures are RPC timeouts rather
than wrong answers (`getblockstats`, `getchaintxstats`); the other 31 are wrong
answers, wrong error codes or wrong shapes. An earlier draft of this line said
"several", which softened the score with a count the artifact does not support.

**Known gaps in this repo** (`receipts/UNIT-BASELINE-v1.0.md`, 2026-09-01): the
unit suite is *measured, not fixed* — 17 failing tests across
`test_misbehavior` (6), `test_netgroup` (5), `test_eviction` (1),
`test_eclipse` (1), `test_parallel_verify_ibd` (1) and `test_snapshot` (3), each
recorded as test-bug-vs-node-bug NOT VERIFIED. These sit in modules using the
stdlib `unittest`, whose failures the "2177/2177 green" `unittest2` summary
never counted. 112 of the 223 `tests/test_*.nim` files are never imported by
`tests/test_all.nim`, and 8 of those do not compile. The nightly assumeUTXO
snapshot-boot gate is a declared carve-out for nimrod
(`BOOTSMOKE_EXPECTED_FAIL=rustoshi nimrod`,
`receipts/boot-smoke-4-red-triaged-2026-08-16.md:91-118`), not a passing gate.

**Fleet-wide comparison:** `receipts/RELEASE-v1.0-SCORECARD.md` in the hashhog
meta-repo, which is **not public** — see the note below.

> **The cited paths are NOT publicly readable — do not treat them as evidence.**
> Paths beginning `receipts/`, `tools/`, `docs/` and `CORE-PARITY-AUDIT/` refer to
> the hashhog meta-repo, which is a **private** repository, not to this one. They
> are provenance for the maintainers. From outside, any claim resting only on such
> a path is **unverified**, and you should read it as such.
>
> Two of those paths are unreadable even with the meta-repo in hand: the R5 probe
> JSON is gitignored (`.gitignore:60  tools/diff-test-artifacts/`) and so are the
> nightly `diffguard-*.log` files (`.gitignore:43  *.log`). Regenerate the probe
> JSON with `python3 tools/r5_probe.py` against a running fleet.
>
> **What you can check from this repository alone:** build it, run its own test
> suite, and reproduce its behaviour against Bitcoin Core yourself. That is the
> evidence this repo actually ships.

## Quick Start

### Build from Source

Toolchain: Nim >= 2.0.0 (`nimrod.nimble`); the Docker image pins `nimlang/nim:2.0.2` (`Dockerfile`) and the tagged validator was built with Nim 2.2.8 / nimble 0.20.1 (`REPRODUCIBLE-BUILD.md`). Install Nim via [choosenim](https://github.com/dom96/choosenim) or a release tarball — the Debian `nim` package is not verified for this project. `nimble setup` fetches the Nim deps (chronos, chronicles, stew, nimcrypto, httpbeast, jsony) from the network.

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt-get install -y librocksdb-dev libsecp256k1-dev libsqlite3-dev

# Build
nimble setup
nimble build -d:release

# Run on testnet4
./bin/nimrod --network=testnet4 start

# Show help
./bin/nimrod --help
```

## Features

- Full block and transaction validation (BIP-16, BIP-34, BIP-65, BIP-66, BIP-68, BIP-141, BIP-143, BIP-146, BIP-147)
- Script interpreter supporting P2PKH, P2SH, P2WPKH, P2WSH, and P2TR
- SegWit-aware serialization (txid, wtxid, witness discount)
- MINIMALIF and witness cleanstack enforcement
- Headers-first sync with anti-DoS (PRESYNC/REDOWNLOAD two-phase sync, commitment verification)
- Parallel block downloads with sliding window and adaptive timeouts
- Multi-layer UTXO cache (CoinsView hierarchy, dirty/fresh tracking, memory-aware flushing)
- RocksDB storage with column families via FFI
- Flat file block storage (blk*.dat, 128 MiB max, 16 MiB pre-alloc) and undo data (rev*.dat)
- Transaction mempool with fee/size policy, CPFP tracking, ancestor/descendant limits, and eviction
- Cluster mempool (connected component clustering, greedy linearization, chunk-based mining scores)
- Feerate diagram RBF validation (strict improvement comparison)
- Pay-to-Anchor (P2A) script detection for CPFP fee bumping
- Fee estimation (histogram-based, 85% confirmation threshold)
- Block template generation (BIP-34 coinbase, witness commitment, sigops limit, anti-fee-sniping)
- HD wallet (BIP-32/39/44/49/84/86 key derivation, all address types)
- Coin selection (Branch-and-Bound exact match, Knapsack fallback)
- SQLite wallet storage (keys, UTXOs, transactions)
- Wallet encryption (AES-256-CBC, passphrase-based key derivation)
- Address labels (setlabel, getaddressesbylabel, listlabels)
- PSBT support (BIP-174/BIP-370: create, decode, combine, finalize)
- Output descriptors (BIP-380-386: derive addresses, import)
- Compact block relay (BIP-152: short IDs, cmpctblock/getblocktxn/blocktxn, mempool reconstruction)
- BIP-9 version bits (soft fork signaling state machine)
- BIP-133 feefilter with Poisson delay and hysteresis
- Block pruning (auto/manual, 550 MiB minimum, 288-block safety margin)
- assumeUTXO (snapshot creation/loading via dumptxoutset/loadtxoutset RPCs)
- REST API (read-only: block, headers, tx, getutxos, mempool in JSON/binary/hex)
- Misbehavior scoring (100-point threshold, persistent ban list)
- Stale peer eviction (chain sync timeout, ping timeout, headers timeout)
- Inventory trickling (Poisson-distributed tx relay, immediate block relay)
- Checkpoint verification (minimum chain work, assume-valid, fork rejection)
- Regtest mode with generate, generatetoaddress, generatetodescriptor, generateblock RPCs
- Parallel signature verification for IBD performance
- secp256k1 bindings via libsecp256k1 FFI (ECDSA and Schnorr)

## Configuration

### CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-d, --datadir=DIR` | Data directory | `~/.nimrod` |
| `-n, --network=NET` | Network: mainnet, testnet3, testnet4, regtest | `mainnet` |
| `--testnet` | Use testnet3 | |
| `--regtest` | Use regtest | |
| `--rpcport=PORT` | RPC port | `8332` |
| `-p, --port=PORT` | P2P port | `8333` |
| `-l, --loglevel=LEVEL` | Log level: trace, debug, info, warn, error | `info` |
| `--maxconnections=N` | Maximum peer connections | `125` |
| `--rpcuser=USER` | RPC username | |
| `--rpcpassword=PASS` | RPC password | |
| `--bind=ADDR` | P2P bind address | `0.0.0.0` |
| `--norpc` | Disable RPC server | |
| `--prune=SIZE_MB` | Enable pruning to keep SIZE_MB of blocks (min: 550) | disabled |

### Config File

nimrod reads `$datadir/nimrod.conf` in key=value format:

```ini
# Network: mainnet, testnet3, regtest
# network=mainnet

# P2P and RPC ports
# port=8333
# rpcport=8332

# Maximum peer connections
# maxconnections=125

# Log level: trace, debug, info, warn, error
# loglevel=info

# Enable pruning (only keep last N MB of blocks)
# prune=550

# Add a peer to connect to
# addnode=192.168.1.1:8333

# Whitelist an IP address (exempt from DoS limits)
# whitelist=192.168.1.0/24
```

### Subcommands

| Command | Description |
|---------|-------------|
| `start` | Start the node |
| `stop` | Stop a running node |
| `getinfo` | Get node information |
| `getblock <hash>` | Get block by hash |
| `sendrawtransaction <hex>` | Broadcast raw transaction |
| `getbalance` | Get wallet balance |
| `sendtoaddress <addr> <amount>` | Send to address |
| `getnewaddress` | Get new receiving address |

## RPC API

> **Parity note.** These methods are modelled on Bitcoin Core's, but shape parity is not
> behaviour parity. On the 2026-09-01T18:26:42Z operator probe nimrod answers 52 of the
> 103 probed methods correctly against Core's 85, and 33 probes fail — some of them RPC
> timeouts rather than wrong answers
> (`tools/diff-test-artifacts/r5-probe/20260901T182642Z.json`).

### Blockchain

| Method | Description |
|--------|-------------|
| `getblockchaininfo` | Returns blockchain processing state info |
| `getblockcount` | Returns height of the most-work fully-validated chain |
| `getbestblockhash` | Returns hash of the best (tip) block |
| `getblockhash` | Returns hash of block at given height |
| `getblock` | Returns block data for a given hash |
| `getblockheader` | Returns block header data |
| `getdifficulty` | Returns proof-of-work difficulty |
| `getchaintips` | Returns information about all known tips in the block tree |
| `gettxoutsetinfo` | Returns statistics about the UTXO set |
| `pruneblockchain` | Prunes blockchain up to specified height |
| `invalidateblock` | Marks a block as invalid |
| `reconsiderblock` | Removes invalidity status from a block |
| `preciousblock` | Treats a block as if it were received first at its height |
| `dumptxoutset` | Dumps the UTXO set to a file |
| `loadtxoutset` | Loads a UTXO snapshot for assumeUTXO |

### Transactions

| Method | Description |
|--------|-------------|
| `getrawtransaction` | Returns raw transaction data |
| `sendrawtransaction` | Submits a raw transaction to the network |
| `decoderawtransaction` | Decodes a hex-encoded raw transaction |
| `submitpackage` | Submits a package of transactions |

### Mempool

| Method | Description |
|--------|-------------|
| `getmempoolinfo` | Returns mempool state details |
| `getrawmempool` | Returns all transaction IDs in the mempool |
| `getmempoolentry` | Returns mempool data for a given transaction |

### Network

| Method | Description |
|--------|-------------|
| `getnetworkinfo` | Returns P2P networking state info |
| `getpeerinfo` | Returns data about each connected peer |
| `getconnectioncount` | Returns the number of connections |
| `addnode` | Adds or removes a peer |
| `listbanned` | Lists all banned IPs/subnets |
| `setban` | Adds or removes an IP/subnet from the ban list |
| `clearbanned` | Clears all banned IPs |
| `getzmqnotifications` | Returns ZMQ notification info |

### Mining

| Method | Description |
|--------|-------------|
| `getblocktemplate` | Returns a block template for mining |
| `submitblock` | Submits a new block to the network |
| `estimatesmartfee` | Estimates fee rate for confirmation within N blocks |
| `generate` | Mines blocks (regtest only) |
| `generatetoaddress` | Mines blocks to an address (regtest only) |
| `generatetodescriptor` | Mines blocks to a descriptor (regtest only) |
| `generateblock` | Mines a block with specific transactions (regtest only) |

### Wallet

| Method | Description |
|--------|-------------|
| `getnewaddress` | Generates a new receiving address |
| `getrawchangeaddress` | Generates a new change address |
| `getbalance` | Returns wallet balance |
| `listunspent` | Lists unspent outputs |
| `getwalletinfo` | Returns wallet state info |
| `sendtoaddress` | Sends bitcoin to an address |
| `listtransactions` | Lists wallet transactions |
| `encryptwallet` | Encrypts the wallet with a passphrase |
| `walletpassphrase` | Unlocks an encrypted wallet |
| `walletlock` | Locks the wallet |
| `walletpassphrasechange` | Changes the wallet passphrase |
| `setlabel` | Sets an address label |
| `getaddressesbylabel` | Returns addresses with a given label |
| `listlabels` | Lists all labels |

### Descriptors and PSBT

| Method | Description |
|--------|-------------|
| `getdescriptorinfo` | Analyzes and checksums an output descriptor |
| `deriveaddresses` | Derives addresses from a descriptor |
| `importdescriptors` | Imports output descriptors into the wallet |
| `createpsbt` | Creates a PSBT |
| `decodepsbt` | Decodes a base64 PSBT |
| `combinepsbt` | Combines multiple PSBTs |
| `finalizepsbt` | Finalizes a PSBT |

### Utility

| Method | Description |
|--------|-------------|
| `validateaddress` | Validates a Bitcoin address |
| `stop` | Stops the node |

## Architecture

nimrod leverages Nim's Python-like syntax with C-level performance to implement a complete Bitcoin full node. Core types (TxId, BlockHash, Satoshi, Transaction, Block) use Nim's object system with binary serialization via custom BinaryWriter/BinaryReader types supporting CompactSize encoding and SegWit witness data. Cryptographic operations -- SHA-256d, RIPEMD-160, HASH160, and secp256k1 ECDSA/Schnorr -- are provided through FFI bindings to libsecp256k1, giving native C performance for signature verification.

The script interpreter is implemented as a stack machine supporting all standard script types (P2PKH, P2SH, P2WPKH, P2WSH, P2TR) with full enforcement of BIP-141 witness pubkey type rules, BIP-146 NULLFAIL, BIP-147 NULLDUMMY, MINIMALIF, and witness cleanstack. Sighash computation covers legacy (with FindAndDelete/OP_CODESEPARATOR), SegWit v0 (BIP-143), and Taproot (BIP-341). Sigop cost counting applies the witness discount (legacy 4x, witness 1x, 80K limit per block).

The storage layer uses RocksDB via FFI with column families for blocks, UTXOs, and chain state. A multi-layer CoinsView cache hierarchy tracks dirty/fresh state for efficient batch flushing. Block data is stored in flat blk*.dat files (128 MiB max) with 16 MiB pre-allocation, and undo data in rev*.dat files with checksums for block disconnection during reorgs. The wallet uses SQLite for key, UTXO, and transaction storage, with AES-256-CBC encryption and Branch-and-Bound / Knapsack coin selection.

P2P networking implements TCP connections with version/verack handshakes, DNS seed discovery, and a peer manager enforcing connection limits and misbehavior scoring (100-point threshold with persistent ban lists). Header sync uses a two-phase anti-DoS protocol (PRESYNC/REDOWNLOAD) with commitment verification and minimum chain work thresholds. Block download uses a parallel sliding window with adaptive timeouts. Compact block relay (BIP-152) enables low-latency block propagation using short IDs and mempool reconstruction.

The mempool implements cluster-based transaction management with connected component clustering, greedy linearization, and chunk-based mining scores. RBF validation uses feerate diagram comparison for strict improvement. Fee estimation is histogram-based with an 85% confirmation threshold. Block template generation selects transactions by ancestor feerate with BIP-34 coinbase height encoding, witness commitment, sigops limits, locktime finality checks, and anti-fee-sniping nLockTime.

## Project Structure

```
nimrod/
  src/
    nimrod.nim          # Unified CLI entry point
    primitives/         # Core types and serialization
    crypto/             # Hashing, secp256k1, address encoding
    script/             # Script interpreter
    consensus/          # Params and validation
    storage/            # RocksDB, chainstate, undo files
    network/            # P2P messaging and sync
    mempool/            # Transaction pool
    mining/             # Fees and block templates
    rpc/                # JSON-RPC server
    wallet/             # Full wallet: BnB/Knapsack coin selection, SQLite
    perf/               # Benchmarking and parallel verification
  tests/                # Test suites with Bitcoin Core vectors
    data/               # Test vectors (script, BIP-32, addresses)
  config/
    nimrod.conf         # Example configuration file
  resources/
    bip39-english.txt   # BIP-39 mnemonic wordlist
```

## Running Tests

```bash
nimble test
```

## License

MIT
