# Package
version       = "0.1.0"
author        = "nimrod-dev"
description   = "A Bitcoin full node in Nim"
license       = "MIT"
srcDir        = "src"
bin           = @["nimrod"]

# Dependencies
requires "nim >= 2.0.0"
requires "chronicles >= 0.10.3"
requires "chronos >= 4.0.0"
requires "stew >= 0.2.0"
requires "nimcrypto >= 0.6.0"
requires "rocksdb >= 0.5.0"
requires "httpbeast >= 0.4.1"
requires "jsony >= 1.1.5"
requires "unittest2 >= 0.2.0"

task test, "Run tests":
  exec "nim c -r tests/test_all.nim"

task build_release, "Build release binary":
  exec "nim c -d:release -o:bin/nimrod src/nimrod.nim"
