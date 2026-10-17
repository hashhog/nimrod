# Contributing to nimrod

## Build and test

See [docs/building.md](docs/building.md) for the toolchain. Then:

```bash
nimble setup -y
nimble build -d:release -y
git clone --depth 1 --branch v31.1 https://github.com/bitcoin/bitcoin.git ../bitcoin-core
nimble test
```

The suite reads Bitcoin Core's test vectors from `../bitcoin-core`.

`nimble test` builds every `tests/test_*.nim` into one binary and prints a `[Summary]`
line with the counts. A new test file must be picked up by `tests/test_all.nim`; the
build fails if a file in `tests/` is neither included nor listed in its `ExcludedTests`
with a reason.

New tests use `unittest2`, like the rest of the suite. Format new Nim files with
`nimpretty`; do not reformat files your change does not otherwise touch.

## Pull requests

- One change per pull request, against `master`.
- Every behaviour change comes with a test that fails before the change and passes after
  it. If an existing test asserts the old behaviour, change that test in the same pull
  request and say why.
- Do not delete or skip a test to make the suite pass. If a test pins a known gap, keep
  it skipped with a message that names the gap.
- Update the docs in `docs/` when you change a flag, a config key or an RPC method.

## Commit messages

Conventional-commit prefixes: `fix:`, `feat:`, `perf:`, `refactor:`, `test:`, `docs:`,
`build:`, `ci:`. The subject says what changed; the body says why, and for a fix, how it
was found and how the test reproduces it.

## Consensus changes

nimrod must accept exactly the blocks and transactions Bitcoin Core accepts. A change to
block, transaction or script validation, the UTXO set, or chain selection needs evidence
of Core equivalence in the pull request: the Core source it follows (file and function),
a test that shows the behaviour on a case where the old code and Core disagreed, and the
result of Core's test vectors (`tests/test_script_vectors.nim`) or an equivalent regtest
comparison against a Core node. Also state what could make a valid block invalid, or an
invalid block valid, with your change, and which test covers that.
