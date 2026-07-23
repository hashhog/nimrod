# Reproducible build — nimrod

How to build the nimrod validator and verify it. Part of the tagged-validator
release wrapper (see `SECURITY.md` and `../receipts/PRODUCTION-GATE.md` "three
bars"). This note is staged ahead of the first tag; the pinned release commit +
its authoritative hash are recorded when `v0.1.0-rc1` is cut.

## Reference build (current `master`)

| | |
|---|---|
| Commit | `eaaf8bf` (HEAD at the time of this note) |
| Binary | `nimrod/bin/nimrod` |
| **sha256** | `12904c0bb522978eba43d1385c054c3bcfa9002224ac86225505ed9304ad2aaf` |
| Toolchain | `Nim 2.2.8`, `nimble 0.20.1` |
| Target | `Linux amd64` |
| Build | `nimble build -d:release -y` |

> At tag time, re-record this table for the pinned rc commit.

## Build

```bash
git clone git@github.com:hashhog/nimrod.git
cd nimrod
# install Nim 2.2.8 (via choosenim or your package manager)
nimble build -d:release -y
sha256sum bin/nimrod
```

## Verify

Reproducibility holds **when the toolchain and target match**: same `Nim 2.2.8`,
same `Linux amd64`, a clean checkout of the tagged commit.

**Honest caveats** (a hash mismatch under a *different* environment is expected, not
tampering):
- Nim compiles via C; the resulting binary depends on the Nim version, the backing
  C compiler/libc, and build paths. Different toolchains produce different bytes.
- For an exact match, use the pinned `Nim 2.2.8` on a comparable Linux/glibc host.
- The stronger guarantee this release rests on is **behavioural, not bit-level**:
  the binary validates Bitcoin mainnet in consensus with Bitcoin Core —
  trustless-from-genesis (`--assumevalid=0`), byte-exact at the live tip, crash-
  recovery 3/3, reorg 6/6 (incl. a 110-block deep reorg), clean differential guard,
  full diff-test corpus parity. Run it beside Core with `consensus-diff` as a live
  divergence alarm; that is the intended trust model (validator, **not** custody).

## Scope of this release

- **Is:** a trustless-from-genesis validating node, byte-exact with Core, to run
  beside Core in watchtower mode.
- **Is not:** fund-capable (do not custody funds — see `SECURITY.md`).
- **N/A:** the assumeutxo **snapshot-boot** path is not part of this release. nimrod
  reaches tip by a genuine from-genesis sync, so snapshot-boot is not required; its
  known serve-tip wiring bug (`boot-smoke.sh` red) is filed separately and does not
  gate the from-genesis validator tag. The release-gate smoke check is
  `tools/smoke-harness.sh --node=nimrod` (regtest boot + genesis-state RPC + clean
  shutdown), which passes at the reference commit above.
