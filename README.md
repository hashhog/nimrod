# nimrod

A Bitcoin full node implementation in Nim.

## What is it?

Maybe you've wondered what it takes to validate a Bitcoin transaction from scratch.
nimrod is a from-scratch Bitcoin full node written in Nim that aims to do exactly that.
It leverages Nim's Python-like syntax with C-level performance.

## Current status

- [x] Project scaffold and module structure
- [x] Primitive types (TxId, BlockHash, Satoshi)
- [x] Binary serialization (BinaryWriter/BinaryReader, CompactSize)
- [x] SegWit transaction serialization (witness data, marker/flag)
- [x] txid and wtxid computation
- [x] Cryptographic hashing (SHA-256d, RIPEMD-160, HASH160)
- [x] secp256k1 bindings (ECDSA/Schnorr via libsecp256k1 FFI)
- [x] Base58Check encoding (legacy P2PKH, P2SH addresses)
- [x] Bech32/Bech32m encoding (segwit P2WPKH, P2WSH, P2TR addresses)
- [x] Address encoding/decoding for all Bitcoin address types
- [x] Script interpreter (P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
- [x] BIP-141 witness pubkey type enforcement (compressed keys only in witness v0)
- [x] BIP-146 NULLFAIL enforcement (failed sig checks require empty signatures)
- [x] BIP-147 NULLDUMMY enforcement (CHECKMULTISIG dummy must be empty)
- [x] Sighash computation (legacy, segwit v0, taproot)
- [x] Consensus parameters (mainnet, testnet3, regtest)
- [x] Difficulty target functions (compact/target conversion)
- [x] Genesis block construction and verification
- [x] Block/transaction validation
- [x] RocksDB storage (column families via FFI, UTXO set, block index)
- [x] Chainstate management (atomic block connect/disconnect, write batches)
- [x] UTXO set manager (cache, coinbase maturity, reorg support)
- [x] P2P message serialization (typed case object, all message types)
- [x] Peer connection (TCP, message framing, version handshake, ping/pong)
- [x] Peer manager (DNS discovery, connection limits, banning, message routing)
- [x] Block synchronization
- [x] Headers-first sync (256-bit work calculation, most-work chain selection)
- [x] Full initial block download (parallel download, sliding window, adaptive timeouts)
- [x] Transaction mempool (fee/size policy, CPFP tracking, eviction)
- [x] Fee estimation (histogram-based, 85% confirmation threshold)
- [x] Block template generation (BIP-34 coinbase, witness commitment, sigops limit)
- [x] JSON-RPC server (Bitcoin Core compatible, HTTP Basic auth)
- [x] HD Wallet (BIP-32/39/44/84/86 key derivation, P2WPKH signing)
- [x] Unified CLI (subcommands for node, RPC, wallet; config file; signal handlers)
- [x] Comprehensive test suite (unit tests, integration tests, Bitcoin Core vectors)
- [x] Performance optimization (parallel sig verification, UTXO cache, RocksDB tuning)
- [ ] Relay mode (post-IBD block/tx propagation)

## Quick start

```bash
nimble build
./nimrod --help
./nimrod --network=regtest start
./nimrod --network=regtest getinfo
```

## Project structure

```
nimrod/
├── src/
│   ├── nimrod.nim          # Unified CLI entry point
│   ├── primitives/         # Core types and serialization
│   ├── crypto/             # Hashing, secp256k1, address encoding
│   ├── script/             # Script interpreter
│   ├── consensus/          # Params and validation
│   ├── storage/            # RocksDB and chainstate
│   ├── network/            # P2P messaging and sync
│   ├── mempool/            # Transaction pool
│   ├── mining/             # Fees and block templates
│   ├── rpc/                # JSON-RPC server
│   ├── wallet/             # HD wallet, BIP-32/39 key derivation
│   └── perf/               # Benchmarking and parallel verification
├── tests/                  # Test suites with Bitcoin Core vectors
│   └── data/               # Test vectors (script, BIP-32, addresses)
└── resources/              # BIP39 wordlist
```

## Running tests

```bash
nimble test
```
