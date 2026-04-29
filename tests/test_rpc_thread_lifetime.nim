## Regression test for RPC thread handle lifetime (rpc_thread.nim).
##
## The original `rpc_thread.nim` returned a `RpcThreadHandle` that the caller
## was expected to keep alive for the lifetime of the process.  The call site
## in `nimrod.nim::startNode` had instead `discard`-ed the result, which
## caused the inner `Thread[RpcServer]` storage to be destroyed by ARC the
## moment the temporary went out of scope — while the freshly-spawned
## pthread was still reading `t.dataFn` / `t.data` from `addr(t)`.  The
## resulting use-after-free manifested as a cryptic top-level
##
##     SIGSEGV: Illegal storage access. (Attempt to read from nil?)
##     No stack traceback available
##
## right after `starting P2P listener` on a fresh datadir.  Bug was
## deterministic on regtest (every run) and flaky on testnet/mainnet
## (depending on whether the new pthread had read its arguments before the
## destructor fired).  This locked the entire BIP-324 v2 interop matrix —
## every `*-nimrod` and `nimrod-*` pair reported FAIL-launch because nimrod
## exited immediately on startup.
##
## Fix: `NodeState` now owns the handle as `state.rpcThread`, and
## `startNode` assigns instead of discarding.  This test exercises the same
## pattern: spawn, hold the handle, sleep long enough for the pthread to
## have entered chronos, then drop the handle and verify nothing crashed.
##
## We do not exercise the actual RPC server path here (that requires a full
## ChainState / PeerManager / Mempool stack and is covered by the
## bip324-interop-matrix smoke test).  This test is purely about the
## lifetime contract of `startRpcThread`'s return value.

import std/[os, atomics]
import unittest2

# Mirror just enough of the rpc_thread.nim shape to test the lifetime
# contract without dragging in the entire RPC server stack.
type
  FakeRpc = ref object
    started: ptr Atomic[bool]

  FakeHandle = ref object
    thread: Thread[FakeRpc]

proc fakeMain(rpc: FakeRpc) {.thread.} =
  ## Sleep briefly to widen the race window where the original bug
  ## manifested: in the unfixed code, `addr(t)` would already point at
  ## freed memory by the time this proc reads `rpc` (the `data` field of
  ## the Thread[FakeRpc] object).
  sleep(50)
  rpc.started[].store(true)

proc startFakeThread(rpc: FakeRpc): FakeHandle =
  result = FakeHandle()
  createThread(result.thread, fakeMain, rpc)

suite "RPC thread handle lifetime":
  test "handle held by ref keeps the pthread's storage alive":
    var done: Atomic[bool]
    done.store(false)
    let rpc = FakeRpc(started: addr done)

    # Hold the handle on a long-lived ref — analogous to
    # `NodeState.rpcThread = startRpcThread(...)`.
    let handle = startFakeThread(rpc)

    # Wait for the pthread to flip the flag.  If the handle were
    # `discard`-ed instead, the pthread would race with the destructor
    # on its `addr(t)` argument and either crash or never run.
    var waited = 0
    while not done.load() and waited < 1000:
      sleep(5)
      inc waited
    check done.load()

    # Join cleanly so the pthread doesn't outlive the test.
    joinThread(handle.thread)
