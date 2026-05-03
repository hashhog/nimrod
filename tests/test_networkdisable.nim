## Tests for NetworkDisable RAII gate around `dumptxoutset rollback`.
##
## Mirrors Bitcoin Core's NetworkDisable wrapper around TemporaryRollback
## in rpc/blockchain.cpp::dumptxoutset. We exercise the
## `blockSubmissionPaused` flag directly and confirm the gate predicate
## is wired correctly.

import unittest2
import ../src/rpc/server

# Helper: bare-bones RpcServer for gate-only tests. We don't need a
# functioning chain to exercise the flag.
proc minimalRpcServer(): RpcServer =
  RpcServer(
    port: 0,
    running: false,
    blockSubmissionPaused: false
  )

suite "NetworkDisable gate (dumptxoutset rollback)":
  test "isBlockSubmissionPaused defaults to false":
    let rpc = minimalRpcServer()
    check not rpc.isBlockSubmissionPaused()

  test "setting flag pauses, clearing flag resumes":
    let rpc = minimalRpcServer()
    rpc.blockSubmissionPaused = true
    check rpc.isBlockSubmissionPaused()
    rpc.blockSubmissionPaused = false
    check not rpc.isBlockSubmissionPaused()

  test "isBlockSubmissionPaused safe on nil rpc":
    # The gate is called from handleSubmitBlock which always has a valid
    # rpc, but defensive nil-handling avoids surprises in tests/scripts.
    let rpc: RpcServer = nil
    check not rpc.isBlockSubmissionPaused()
