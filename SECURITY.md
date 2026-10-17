# Security policy

nimrod is an experimental, independent re-implementation of a Bitcoin full node, written
for research and testing. It has not been audited. Do not use it to hold or move real
funds, and do not rely on it as your only view of the Bitcoin chain.

## Supported versions

Only the latest commit on `master` receives fixes.

## Reporting a vulnerability

Do not open a public GitHub issue for a vulnerability in consensus, P2P or wallet code.
Report it privately by email to `max@dockyard.navy`.

Please include the affected code path, a deterministic reproduction (a regtest script, a
raw block or transaction, or a malformed P2P message), the impact, and a suggested fix if
you have one. You will get a reply, a fix and disclosure timeline agreed with you, and
credit if you want it.

## In scope

- Consensus divergence from Bitcoin Core: nimrod accepting a block or transaction that
  Core rejects, or rejecting one Core accepts.
- Remotely triggerable crashes, hangs, or memory or disk exhaustion through P2P, RPC or
  REST input.
- Chainstate corruption after a crash or an unclean shutdown.
- Wallet bugs that sign with the wrong key, produce transactions the network rejects, or
  make backups unrecoverable.
- RPC authentication bypass.

## Out of scope

- Sync speed and resource use that is merely high.
- Attacks that need an already-compromised host or local access to the data directory.
- Known limitations listed in [docs/status.md](docs/status.md#known-limitations) and
  [docs/rpc.md](docs/rpc.md#known-differences-from-core).
