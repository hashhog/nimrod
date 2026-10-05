## Process-wide fatal latch — nimrod's Bitcoin Core AbortNode / FatalError.
##
## Gate 6 (docs/RELEASE-CHECKLIST.md): a resource failure (a chainstate write
## or flush that fails, a coins-DB read that keeps failing, a script check
## that dies with an internal error twice) is never a statement about a block.
## Core's answer is `FatalError` -> `AbortNode` (validation.cpp:2136,
## node/abort.cpp): log, flag the node as shutting down, stop connecting
## blocks, and exit WITHOUT writing the in-memory state that the failure
## left behind. It never marks the block and never punishes a peer.
##
## Once `abortNode` has run:
##   * every chain-changing entry (acceptAndConnectBlock, the P2P applyBlock,
##     handleReorg, submitblock, the mempool) refuses with `fatalErrorToken`,
##     which every classifier reads as "not a verdict";
##   * the shutdown path skips the IBD-batch flush and the UTXO-cache flush
##     (the very state the failed write could not make durable) and the
##     process exits 1, so systemd's Restart=on-failure brings it back and the
##     node replays from the last state that DID commit.
##
## The latch is one-way for the life of the process. `abortAction` is what
## turns it into a shutdown: production (`setupSignalHandlers`) installs
## "SIGTERM to self", tests leave it nil so the latch can be asserted without
## killing the test runner.

import std/[atomics, locks, strutils]
import chronicles

const fatalErrorToken* = "fatal-error"
  ## Prefix of every error string produced while the latch is set (or by the
  ## failure that set it). Never a verdict: blockFailureKindOfApplyError,
  ## blockFailureKindOfToken and bip22RejectToken all read it as local.

var gFatal: Atomic[bool]
var gFatalLock: Lock
var gFatalMsg: string
var gAbortAction: proc() {.gcsafe, raises: [].}

initLock(gFatalLock)

proc isFatal*(): bool {.gcsafe, raises: [].} =
  ## True once a fatal system fault was latched (Core: ShutdownRequested()
  ## after AbortNode).
  gFatal.load(moAcquire)

proc fatalMessage*(): string {.gcsafe, raises: [].} =
  {.cast(gcsafe).}:
    withLock gFatalLock:
      result = gFatalMsg

proc fatalRefusal*(): string {.gcsafe, raises: [].} =
  ## The error string a chain-changing entry returns while latched.
  fatalErrorToken & ": node is shutting down after a fatal error (" &
    fatalMessage() & ")"

proc isFatalFailure*(msg: string): bool {.gcsafe, raises: [].} =
  ## True when an error string is (or was produced under) the fatal latch.
  isFatal() or msg.startsWith(fatalErrorToken)

proc setAbortAction*(action: proc() {.gcsafe, raises: [].}) {.gcsafe, raises: [].} =
  {.cast(gcsafe).}:
    gAbortAction = action

proc abortNode*(msg: string) {.gcsafe, raises: [].} =
  ## Latch the fatal state (first caller wins) and request shutdown.
  if gFatal.exchange(true, moAcquireRelease):
    return
  {.cast(gcsafe).}:
    withLock gFatalLock:
      gFatalMsg = msg
    try:
      error "FATAL (AbortNode): a system fault left the chainstate unable to " &
            "advance safely — refusing to connect blocks, NOT marking any " &
            "block invalid, NOT punishing any peer; exiting without flushing",
            reason = msg
    except Exception:
      discard
    let action = gAbortAction
    if action != nil:
      action()

proc noteFault*(msg: string) {.gcsafe, raises: [].} =
  ## Log a system fault that is being retried (not yet fatal).
  try:
    warn "system fault (retrying; not a block verdict)", detail = msg
  except Exception:
    discard

proc resetFatalForTest*() {.gcsafe, raises: [].} =
  ## Tests only: clear the latch between cases.
  {.cast(gcsafe).}:
    withLock gFatalLock:
      gFatalMsg = ""
  gFatal.store(false, moRelease)

proc retryOnceOrAbort*(what: string, op: proc() {.gcsafe.}): bool {.gcsafe, raises: [].} =
  ## Run a durability step (a batch write, a flush). On failure retry it ONCE;
  ## if the retry fails too, latch the node fatal and return false. The caller
  ## must not forget any in-memory state the step was meant to make durable
  ## unless this returns true.
  var firstErr = ""
  try:
    op()
    return true
  except Exception as e:
    firstErr = e.msg
  try:
    warn "durable write failed; retrying once", step = what, error = firstErr
  except Exception:
    discard
  try:
    op()
    return true
  except Exception as e:
    abortNode(what & " failed twice: " & firstErr & " / " & e.msg)
    return false
