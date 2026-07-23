# Security Policy — nimrod

nimrod is a from-scratch Bitcoin full-node implementation in Nim, part of the
[hashhog](https://github.com/hashhog) fleet of ten independent nodes that
cross-validate each other and Bitcoin Core. Security — specifically, tracking
Bitcoin consensus exactly — is the entire purpose of the node.

## Project maturity — read this first

nimrod is being released on the **tagged-validator** bar: a node you can build,
run *beside* Bitcoin Core in watchtower mode, and trust to track consensus. It is
the one node in the fleet (besides the flagships) with a genuine, continuous
**trustless-from-genesis validation** (a full `--assumevalid=0` sync, scripts on),
and it is **byte-exact with Bitcoin Core at the live chain tip**.

**It is NOT fund-capable.** Do not custody funds on nimrod. The intended trust
model is: run it alongside Core with `consensus-diff` as a live divergence alarm.
The funds-grade ladder (see `../receipts/PRODUCTION-GATE.md`) is a separate, later,
flagship-first track.

There are no fund-grade guarantees and, until the first tag ships, no versioned
release. Run from a pinned commit and expect breaking changes.

## Supported versions

| Version | Supported |
|---------|-----------|
| pre-release (`master`) | Best-effort; no security SLA until the first tagged release |

## Reporting a vulnerability

**Please do NOT open a public GitHub issue** for anything in the consensus, P2P, or
resource-handling paths — a public report could put real Bitcoin nodes at risk.

Report privately to the maintainer:

- **Email:** `max@dockyard.navy`  <!-- TODO(max): confirm or replace with a dedicated security alias -->

Include: the affected path (consensus / P2P / RPC / resource), a deterministic
reproduction (a diff-test corpus entry, regtest script, or malformed message),
impact, and any suggested fix. We acknowledge receipt, coordinate a fix and
disclosure timeline, and credit you if you wish.

## In scope (highest priority)

- **Consensus divergence** — nimrod accepting a block/tx Core rejects, or vice-versa.
  This is the core concern; nimrod carries 40+ receipted-and-fixed divergences with
  Core `file:line` citations (see `../CORE-PARITY-AUDIT/`).
- **Remotely-triggerable crashes / OOM / resource exhaustion** in the P2P or
  block/tx decode paths.
- **Chainstate corruption on crash** (nimrod passes the P0.5 kill-9 recovery suite
  3/3; regressions are in scope).

## Out of scope

- IBD/sync performance (documented characteristics).
- Issues requiring an already-compromised host.
- The assumeutxo snapshot-boot path — **not a supported feature of this release**
  (nimrod is a from-genesis validator); its known serve-tip wiring bug is tracked
  separately and is not a consensus issue.

## Disclosure

Coordinated disclosure. Consensus fixes are verified with `../tools/verify-fix.sh`
and gated through the differential corpus before they are considered landed; where a
fix affects multiple fleet implementations we port it before public disclosure.
