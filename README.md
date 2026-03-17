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
- [x] BIP-16 P2SH push-only scriptSig enforcement (unconditional consensus rule)
- [x] BIP-141 witness pubkey type enforcement (compressed keys only in witness v0)
- [x] BIP-146 NULLFAIL enforcement (failed sig checks require empty signatures)
- [x] BIP-147 NULLDUMMY enforcement (CHECKMULTISIG dummy must be empty)
- [x] Witness cleanstack enforcement (exactly one true element after execution)
- [x] MINIMALIF enforcement (OP_IF/NOTIF argument must be empty or @[0x01])
- [x] Sighash computation (legacy with FindAndDelete/OP_CODESEPARATOR, segwit v0, taproot)
- [x] Consensus parameters (mainnet, testnet3, testnet4, regtest, signet)
- [x] Difficulty adjustment (mainnet retarget, testnet 20-min rule, BIP94 time-warp fix)
- [x] Genesis block construction and verification
- [x] Block/transaction validation
- [x] Sigop cost counting with witness discount (BIP-141: 80K limit, legacy 4x, witness 1x)
- [x] BIP-68 sequence locks (relative lock-time enforcement in block validation)
- [x] RocksDB storage (column families via FFI, UTXO set, block index)
- [x] Chainstate management (atomic block connect/disconnect, write batches)
- [x] UTXO set manager (cache, coinbase maturity, reorg support)
- [x] Undo data storage (flat file rev*.dat, checksums, block disconnect)
- [x] Flat file block storage (blk*.dat files, 128 MiB max, 16 MiB pre-alloc)
- [x] P2P message serialization (typed case object, all message types)
- [x] Peer connection (TCP, message framing, version handshake, ping/pong)
- [x] Peer manager (DNS discovery, connection limits, banning, message routing)
- [x] Block synchronization
- [x] Headers-first sync (256-bit work calculation, most-work chain selection)
- [x] Full initial block download (parallel download, sliding window, adaptive timeouts)
- [x] Header sync anti-DoS (PRESYNC/REDOWNLOAD two-phase sync, commitment verification)
- [x] Transaction mempool (fee/size policy, CPFP tracking, eviction, ancestor/descendant limits)
- [x] Fee estimation (histogram-based, 85% confirmation threshold)
- [x] Block template generation (BIP-34 coinbase, witness commitment, sigops limit, locktime finality, anti-fee-sniping)
- [x] JSON-RPC server (getblockchaininfo, getnetworkinfo, getpeerinfo, getmempoolinfo, getrawmempool, estimatesmartfee, validateaddress, getblocktemplate, batch requests)
- [x] HD Wallet (BIP-32/39/44/49/84/86 key derivation, all address types)
- [x] Coin selection (Branch-and-Bound exact match, Knapsack fallback)
- [x] SQLite wallet storage (keys, UTXOs, transactions)
- [x] Wallet RPC (getnewaddress, getbalance, listunspent, getwalletinfo)
- [x] Coinbase maturity enforcement (100-block delay before spending)
- [x] Wallet encryption (AES-256-CBC, passphrase-based key derivation)
- [x] Address labels (setlabel, getaddressesbylabel, listlabels)
- [x] Unified CLI (subcommands for node, RPC, wallet; config file; signal handlers)
- [x] Comprehensive test suite (unit tests, integration tests, Bitcoin Core vectors)
- [x] Performance optimization (parallel sig verification, UTXO cache, RocksDB tuning)
- [x] BIP-9 version bits (soft fork signaling state machine, deployment tracking)
- [x] Misbehavior scoring (100-point threshold, persistent ban list, RPC commands)
- [x] Pre-handshake message rejection (VERSION/VERACK enforcement, protocol version check, self-connection detection, 60s timeout)
- [x] Inventory trickling (Poisson-distributed tx relay, per-peer queues, immediate block relay)
- [x] Stale peer eviction (chain sync timeout, ping timeout, headers timeout, extra outbound eviction)
- [x] Checkpoint verification (minimum chain work, assume-valid, fork rejection below checkpoints)
- [x] sendrawtransaction RPC (maxfeerate validation, idempotent mempool handling, inv broadcast)
- [x] getrawtransaction RPC (mempool lookup, txindex lookup, blockhash parameter, verbose output with asm/address)
- [x] Multi-layer UTXO cache (CoinsView hierarchy, dirty/fresh tracking, memory-aware flushing)
- [x] Block pruning (auto/manual deletion of old blk/rev files, 550 MiB minimum, 288-block safety margin)
- [x] Compact block relay (BIP-152 short ID, cmpctblock/getblocktxn/blocktxn, mempool reconstruction)
- [x] Cluster mempool (connected component clustering, greedy linearization, chunk-based mining scores, cluster size limits)
- [x] Feerate diagram RBF validation (diagram construction, interpolation, strict improvement comparison)
- [x] Pay-to-Anchor (P2A) script detection (BIP-TBD: OP_1 <0x4e73> anyone-can-spend for CPFP fee bumping)
- [x] REST API (read-only endpoints: block, headers, tx, getutxos, mempool in JSON/binary/hex formats)

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
│   ├── storage/            # RocksDB, chainstate, undo files
│   ├── network/            # P2P messaging and sync
│   ├── mempool/            # Transaction pool
│   ├── mining/             # Fees and block templates
│   ├── rpc/                # JSON-RPC server
│   ├── wallet/             # Full wallet: BnB/Knapsack coin selection, SQLite
│   └── perf/               # Benchmarking and parallel verification
├── tests/                  # Test suites with Bitcoin Core vectors
│   └── data/               # Test vectors (script, BIP-32, addresses)
└── resources/              # BIP39 wordlist
```

## Running tests

```bash
nimble test
```
