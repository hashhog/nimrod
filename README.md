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
- [x] Script interpreter (stack machine, opcodes)
- [x] Consensus parameters (mainnet, testnet, regtest)
- [x] Block/transaction validation
- [x] RocksDB storage layer
- [x] Chainstate and UTXO management
- [x] P2P network messages
- [x] Peer connection handling (chronos async)
- [x] Block synchronization
- [x] Transaction mempool
- [x] Fee estimation
- [x] Block template generation
- [x] JSON-RPC server
- [x] Basic wallet (key management, addresses)
- [ ] Initial block download
- [ ] Full script verification

## Quick start

```bash
nimble build
./nimrod --help
./nimrod --testnet
```

## Project structure

```
nimrod/
├── src/
│   ├── nimrod.nim          # Main entry point
│   ├── primitives/         # Core types and serialization
│   ├── crypto/             # Hashing and secp256k1
│   ├── script/             # Script interpreter
│   ├── consensus/          # Params and validation
│   ├── storage/            # RocksDB and chainstate
│   ├── network/            # P2P messaging and sync
│   ├── mempool/            # Transaction pool
│   ├── mining/             # Fees and block templates
│   ├── rpc/                # JSON-RPC server
│   └── wallet/             # Key management
├── tests/                  # Test suites
└── config/                 # Configuration files
```

## Running tests

```bash
nimble test
```
