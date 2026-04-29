## rpc_thread.nim - Run the RPC server on a dedicated OS thread.
##
## Problem: when the RPC server ran on the main chronos event loop alongside
## the sync/validation pipeline, a single verifyScripts() call could stall the
## event loop for seconds or minutes per block batch, during which RPC accept()
## and response wouldn't fire. consensus-diff hit its 60s timeout and reported
## nimrod as FAIL every run.
##
## Fix: launch the RPC server on a dedicated OS thread. Each chronos event loop
## is thread-local (getGlobalDispatcher() per thread), so the thread gets its
## own loop. Accept/read/write I/O for RPC no longer competes with block
## validation on the main thread.
##
## Known limitation (v1, not addressed here): a few RPC handlers call
## asyncSpawn against peerManager (broadcastTx, broadcastBlock, etc.). With
## the RPC on a different thread, those futures now spawn on the RPC thread's
## event loop instead of the main thread's. Peer transports are bound to the
## main loop and may not be reachable from the RPC thread, so broadcast-style
## RPCs may no-op or error out from the RPC thread. Read-only RPCs -
## getblockcount, getblockchaininfo, getblockhash, getblock, gettxoutsetinfo,
## etc. - which are the ones consensus-diff and monitoring hit - work.
## Fixing cross-thread broadcast is a follow-up (thread-safe work queue).

import chronos
import chronicles
import ./server

type
  RpcThreadHandle* = ref object
    ## Opaque handle to the background RPC thread.
    thread: Thread[RpcServer]

proc rpcThreadMain(rpc: RpcServer) {.thread.} =
  ## Thread entry point. Drives chronos on this thread until rpc.start()
  ## returns (which happens when rpc.stop() flips rpc.running = false).
  {.gcsafe.}:
    try:
      waitFor rpc.start()
    except CatchableError as e:
      error "RPC thread crashed", error = e.msg

proc startRpcThread*(rpc: RpcServer): RpcThreadHandle =
  ## Create and start a dedicated thread for the RPC server.
  ##
  ## CALLER MUST keep the returned handle alive for the lifetime of the
  ## process — store it on a long-lived ref (e.g. `NodeState.rpcThread`).
  ## Discarding the handle frees the inner `Thread[RpcServer]` storage that
  ## `pthread_create` was given as `addr(t)`.  The new pthread then races
  ## against `=destroy` reading `t.dataFn` / `t.data` from freed (and
  ## possibly reused) memory, which manifests as a SIGSEGV ("Attempt to
  ## read from nil?") deterministically on regtest startup and flakily on
  ## testnet/mainnet depending on scheduling.
  result = RpcThreadHandle()
  createThread(result.thread, rpcThreadMain, rpc)
