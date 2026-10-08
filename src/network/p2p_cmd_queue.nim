## p2p_cmd_queue.nim — RPC -> main-loop command queue for every P2P side
## effect an RPC handler has (NI-6, and NI-5's addnode).
##
## Peers, their chronos transports and the PeerManager tables belong to the
## MAIN thread's event loop. chronos transports are single-loop objects: a
## write from another thread that cannot complete synchronously queues the
## remainder and registers the fd with the CALLING thread's selector, where it
## is not registered -> the write fails but the vector stays queued with
## WritePaused set, and that peer's transport never writes again
## (tools/repro_rpc_thread_send.py). A future completed by one loop also
## resumes its awaiter on the wrong thread, and closeWait/connect from the RPC
## thread put a transport (addnode: a whole peer and its message loop) on the
## RPC dispatcher.
##
## Core: RPC handlers never touch sockets. They call PeerManager /
## CConnman methods that only queue (RelayTransaction -> m_tx_inventory_to_send,
## ping -> m_ping_queued, DisconnectNode -> fDisconnect, AddNode/OpenNetworkConnection
## via ThreadOpenAddedConnections); the network threads do the I/O.
##
## Here: the RPC thread posts a plain-data command (no refs cross threads);
## the main loop drains the queue (PeerManager.p2pCommandLoop) and runs it.

import std/[locks, deques]
import chronos
import chronos/threadsync
import ../primitives/types
import ./messages

type
  P2PCmdKind* = enum
    pcBroadcastTx        ## relay inv for `tx` to every ready peer
    pcBroadcastBlock     ## announce `blk` (headers / inv per BIP-130)
    pcPingAll            ## RPC `ping`: a ping to every ready peer
    pcGetData            ## getdata `invs` to the peer at host:port
    pcDisconnect         ## drop the peer at host:port
    pcDisconnectAddress  ## drop every peer whose address matches `host` (setban)
    pcConnectManual      ## addnode add/onetry: dial host:port as MANUAL

  P2PCmd* = object
    kind*: P2PCmdKind
    tx*: Transaction
    blk*: Block
    host*: string
    port*: uint16
    invs*: seq[InvVector]
    reason*: string

  P2PCmdQueueObj = object
    lock: Lock
    items: Deque[P2PCmd]
    sig: ThreadSignalPtr

  P2PCmdQueue* = ptr P2PCmdQueueObj
    ## Shared allocation for the process lifetime (never freed): referenced by
    ## the RPC server and the main loop without crossing any refcount.

const P2PCmdTickMs* = 50
  ## The drain task also wakes on this tick, so a lost eventfd edge delays a
  ## command by at most this long.

proc newP2PCmdQueue*(): P2PCmdQueue =
  result = cast[P2PCmdQueue](allocShared0(sizeof(P2PCmdQueueObj)))
  initLock(result.lock)
  result.items = initDeque[P2PCmd]()
  let r = ThreadSignalPtr.new()
  if r.isOk:
    result.sig = r.get()

proc post*(q: P2PCmdQueue, cmd: sink P2PCmd) {.gcsafe.} =
  ## Any thread. Never blocks on the network.
  withLock q.lock:
    q.items.addLast(cmd)
  if q.sig != nil:
    discard q.sig.fireSync()

proc takeAll*(q: P2PCmdQueue): seq[P2PCmd] {.gcsafe.} =
  withLock q.lock:
    while q.items.len > 0:
      result.add(q.items.popFirst())

proc pending*(q: P2PCmdQueue): int {.gcsafe.} =
  withLock q.lock:
    result = q.items.len

proc waitForCommands*(q: P2PCmdQueue) {.async.} =
  ## Main loop: returns when a command was posted or after one tick.
  try:
    if q.sig != nil:
      discard await q.sig.wait().withTimeout(chronos.milliseconds(P2PCmdTickMs))
    else:
      await sleepAsync(chronos.milliseconds(P2PCmdTickMs))
  except CatchableError:
    discard
