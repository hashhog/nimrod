# Changelog

All notable changes to nimrod are documented in this file.

## [1.0.0] - 2026-07-31

First stable release of nimrod, a Bitcoin full node written from scratch in Nim.

### Features

- Full block and transaction validation (BIP-16, BIP-34, BIP-65, BIP-66, BIP-68,
  BIP-141, BIP-143, BIP-146, BIP-147) with a script interpreter supporting
  P2PKH, P2SH, P2WPKH, P2WSH, and P2TR
- Headers-first sync with anti-DoS (PRESYNC/REDOWNLOAD two-phase sync,
  commitment verification), parallel block downloads with sliding window
- Multi-layer UTXO cache (CoinsView hierarchy, dirty/fresh tracking,
  memory-aware flushing) over RocksDB column-family storage
- Flat file block storage (blk*.dat, 128 MiB max) and undo data (rev*.dat);
  block pruning (auto/manual, 550 MiB minimum, 288-block safety margin)
- Transaction mempool with fee/size policy, CPFP tracking, Core v31 cluster
  mempool limits, feerate-diagram RBF, and eviction
- HD wallet (BIP-32/39/44/49/84/86), Branch-and-Bound coin selection, SQLite
  storage, AES-256-CBC encryption, labels, PSBT (BIP-174/370), descriptors
  (BIP-380-386), taproot key-path signing
- Compact block relay (BIP-152), BIP-324 v2 transport (outbound by default,
  v1 fallback), BIP-155 addrv2, BIP-157/158 compact block filters
- assumeUTXO snapshot creation/loading (dumptxoutset/loadtxoutset RPCs)
- assumevalid script-skip gate, checkpoint verification, minimum chain work
- Block template generation (BIP-34 coinbase, witness commitment, sigops
  limit, anti-fee-sniping), parallel signature verification for IBD
- JSON-RPC + read-only REST API, ZMQ notifications, regtest mode with
  generate/generatetoaddress/generatetodescriptor/generateblock

### Consensus / Core-parity fixes since 0.1.0

- Gate the 288-block reorg cap on pruning: archive nodes follow the most-work
  valid chain at any depth, matching Core's unbounded ActivateBestChainStep
  (MIN_BLOCKS_TO_KEEP is a pruning floor, not a consensus reorg limit)
- Reject a consensus-invalid heavier side branch instead of storing it
  inconclusive; enforce BIP-68 + BIP-30 on the reorg-connect path
- Enforce coinbase subsidy+fees ceiling (bad-cb-amount), in-block
  double-spend reject, coinbase maturity not skipped by assumevalid,
  coinbase sigops counted in context-free CheckBlock (bad-blk-sigops)
- Unconditional P2SH|WITNESS|TAPROOT script flags with Core's replace-then-OR
- Tapscript BIP-342 sighash commits the executed OP_CODESEPARATOR position;
  MAX_STACK_SIZE after pushes, codesep reset, WITNESS_UNEXPECTED parity
- Core-exact reject tokens: "too-little-chainwork", "time-too-new", bare
  reject tokens on mempool RPC paths

### P2P / RPC / wallet fixes

- BIP324 v2 outbound by default with v1 fallback on post-v2 handshake failure
- Request wtxid-announced transactions via MsgWtx getdata
- getpeerinfo.network computed from peer addr; getmempoolentry nested fees{}
- getnetworkinfo subversion now reports /nimrod:1.0.0/
- getdeploymentinfo/getblockchaininfo buried-deployment "active" flag now uses
  Core's DeploymentActiveAfter semantics (active from one height below the
  activation height); previously off by one vs Core
- getNetGroup now matches Core netgroup.cpp for local/unroutable addresses:
  they collapse to a single group per address family (bare net-class byte,
  no address bits) instead of separate local/unroutable buckets; /16 and /32
  grouping applies to routable addresses only
- --conf and the default <datadir>/nimrod.conf are now actually honored:
  the config file is loaded before CLI flags are applied (CLI takes
  precedence, matching Core init.cpp); previously the file was parsed into
  a discarded copy and silently ignored
- --dbcache now actually bounds the hot UTXO cache (was a dead flag for
  RocksDB); IBD no longer wipes the full UTXO cache every 2000 blocks

### Build / release engineering

- Toolchain: Nim 2.2.8 (Dockerfile pin updated from nimlang/nim:2.0.2)
- nim.cfg adds an rpath entry for user-local lib64 (librocksdb/libsecp256k1)
- CI and release workflows re-enabled (.github/workflows/ci.yml, release.yml)

### Known issues / notes

- assumeUTXO serve-tip wiring is a documented known gap and is out of scope
  for this tag (snapshot RPCs work; serving from an assumeUTXO tip is not
  yet wired end-to-end)
- REPRODUCIBLE-BUILD.md records the reference-build sha for an older commit
  (3 commits behind this release's HEAD); re-record the table at tag time
