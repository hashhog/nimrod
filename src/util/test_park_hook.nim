## test_park_hook.nim — TEST-ONLY: park a chainstate mutation at a named race
## point so an external harness can deliver a signal (SIGTERM) exactly there.
##
## Compiled only with -d:nimrodRaceHooks (tests/config.nims sets it for the
## unit suite; a release build never defines it, so `installTestParkHook` is
## an empty proc and every `racePoint` in storage/chainstate.nim is `discard`).
## Even in a hooks build it is inert unless NIMROD_TEST_PARK_POINT is set, and
## it fires only while the arm file exists (one-shot: it deletes the file).
##
##   NIMROD_TEST_PARK_POINT   race point name, e.g. connect.midcache
##   NIMROD_TEST_PARK_ARM     arm file; the hook fires only if it exists
##   NIMROD_TEST_PARK_MARKER  written when parked: "<pid> <tid> <point> <hash>"
##   NIMROD_TEST_PARK_MS      how long to stay parked (default 4000)
##
## Used by tools/ni4-shutdown-repro.py (meta-repo) for the NI-4 reproducer.

when defined(nimrodRaceHooks):
  import std/[os, posix, strutils, times]
  import ../primitives/types
  import ../storage/chainstate

  var parkPoint, parkArm, parkMarker: string
  var parkMs = 4000

  proc parkHook(point: string, hash: BlockHash) {.nimcall, gcsafe, raises: [].} =
    {.cast(gcsafe).}:
      if point != parkPoint: return
      if parkArm.len > 0 and not fileExists(parkArm): return
      try:
        if parkArm.len > 0: removeFile(parkArm)
        if parkMarker.len > 0:
          writeFile(parkMarker, $getpid() & " " & $getThreadId() & " " &
                    point & " " & $hash & "\n")
      except CatchableError, IOError:
        discard
      # Sleep in small steps: a signal handler that RETURNS (the fixed node)
      # lets the park finish and the connect complete; a handler that quits
      # inside the park (the deployed node) never comes back here.
      let deadline = epochTime() + parkMs.float / 1000.0
      while epochTime() < deadline:
        discard posix.usleep(10_000)

  proc installTestParkHook*() =
    parkPoint = getEnv("NIMROD_TEST_PARK_POINT")
    if parkPoint.len == 0: return
    parkArm = getEnv("NIMROD_TEST_PARK_ARM")
    parkMarker = getEnv("NIMROD_TEST_PARK_MARKER")
    try: parkMs = parseInt(getEnv("NIMROD_TEST_PARK_MS", "4000"))
    except ValueError: discard
    raceHook = parkHook
    echo "TEST PARK HOOK ARMED point=" & parkPoint & " arm=" & parkArm
else:
  proc installTestParkHook*() = discard
