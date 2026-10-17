# Building nimrod

## Toolchain

- Nim 2.2 and nimble. The tree is built and tested with Nim 2.2.8 and nimble 0.20.1.
  `nimrod.nimble` asks for Nim >= 2.0.0, but older 2.0.x releases are not tested. The
  easiest install is [choosenim](https://github.com/nim-lang/choosenim):
  `choosenim 2.2.8`.
- A C compiler (gcc or clang). Nim compiles to C. One C file,
  `src/crypto/sha256_shani.c`, is compiled in for SHA-NI accelerated hashing.
- System libraries, linked dynamically (`nim.cfg` lists them): RocksDB, libsecp256k1,
  SQLite 3, Snappy, LZ4, zlib, and the C++ runtime that RocksDB needs.

On Debian or Ubuntu (tested on Debian 13, which ships RocksDB 9.10 and libsecp256k1 0.5.0):

```bash
sudo apt-get install -y build-essential git librocksdb-dev libsecp256k1-dev libsqlite3-dev libsnappy-dev liblz4-dev zlib1g-dev
```

The Nim packages (chronos, chronicles, stew, nimcrypto, httpbeast, jsony, unittest2 and
their dependencies) are pinned in `nimble.lock`. `nimble setup` fetches them and writes
`nimble.paths`, which `config.nims` includes so that plain `nim c` finds them too.

## Build

```bash
nimble setup -y
nimble build -d:release -y
./bin/nimrod --version
```

The binary is `bin/nimrod`. `nimble build_release` does the same build with an explicit
`nim c -d:release -o:bin/nimrod src/nimrod.nim`.

## Build variants

`nim.cfg` defines three variants:

| Define | Effect |
|---|---|
| `-d:release` | `--opt:speed`, `-O3`, `-march=native`. Use this for anything but debugging. |
| `-d:debug` | Native debugger info, stack and line traces. |
| `-d:profile` | Nim's built-in profiler with stack traces. |

`-march=native` means a release binary is tuned for, and may only run on, the CPU it was
built on. To build a binary for another machine, build it on that machine.

A debug build:

```bash
nim c -d:debug -o:bin/nimrod-debug src/nimrod.nim
./bin/nimrod-debug --version
```

## Tests

The suite needs a Bitcoin Core source checkout at `../bitcoin-core` for its test
vectors; see [status.md](status.md#test-suite) for the command, what it runs and how
long it takes.

## Reproducible builds

nimrod does not produce bit-identical binaries across machines. The output depends on
the Nim version, the C compiler and libc, the build path, and (through `-march=native`)
the build CPU. Two builds of the same commit with the same toolchain on the same host
produce the same `bin/nimrod`; to check:

```bash
nimble build -d:release -y && sha256sum bin/nimrod > "${TMPDIR:-/tmp}/nimrod.sha256"
touch src/nimrod.nim && nimble build -d:release -y && sha256sum -c "${TMPDIR:-/tmp}/nimrod.sha256"
```

The stronger check is behavioural: run the test suite and the steps in
[status.md](status.md) against your own build.

## Docker

The `Dockerfile` and `docker-compose.yml` in the repository root are not maintained and
are not tested; they do not install every library listed above. Build from source
instead.
